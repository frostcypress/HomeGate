// Package frontend is a bounded, allowlisted bridge to the existing configuration
// rules. The modern browser renders JavaScript views; it never renders Lua HTM.
package frontend

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"homegate.local/homegate/internal/config"
)

//go:embed controller.lua routes.json
var rules embed.FS

type Request struct {
	Route string            `json:"route"`
	Form  map[string]string `json:"form"`
	Write bool              `json:"write"`
}
type Result struct {
	APIVersion int               `json:"api_version"`
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Template   string            `json:"template,omitempty"`
	Data       any               `json:"data,omitempty"`
	Body       string            `json:"body,omitempty"`
	Redirect   string            `json:"redirect,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}
type Host interface {
	Shell(context.Context, string) (string, int)
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Remove(string) error
	Stat(string) (map[string]any, error)
	Chmod(string, uint32) error
	Load(context.Context, string) (*Document, error)
	Commit(context.Context, *Document) error
	Begin(context.Context) (func(bool) error, error)
}
type Engine struct {
	Host    Host
	Version string
}
type route struct {
	Handler string `json:"handler"`
	Write   bool   `json:"write"`
}

var allowedRoutes = func() map[string]route {
	var entries map[string]route
	raw, _ := rules.ReadFile("routes.json")
	_ = json.Unmarshal(raw, &entries)
	return entries
}()

func Routes() map[string]route {
	result := make(map[string]route, len(allowedRoutes))
	for k, v := range allowedRoutes {
		result[k] = v
	}
	return result
}

var fieldName = regexp.MustCompile(`^[a-zA-Z0-9_]{1,96}$`)

func (e Engine) Run(ctx context.Context, request Request) (result Result) {
	result = Result{APIVersion: 1, OK: false, Headers: map[string]string{}}
	var response strings.Builder
	defer func() { result.Body = response.String() }()
	entry, found := allowedRoutes[request.Route]
	if !found {
		result.Error = "Unknown HomeGate route"
		return result
	}
	if entry.Write && !request.Write {
		result.Error = "Write permission required"
		return result
	}
	if len(request.Form) > 4096 {
		result.Error = "Too many fields"
		return result
	}
	total := 0
	for key, value := range request.Form {
		if !fieldName.MatchString(key) || strings.ContainsRune(value, 0) {
			result.Error = "Invalid request field"
			return result
		}
		total += len(key) + len(value)
	}
	if total > 2*1024*1024 {
		result.Error = "Request exceeds size limit"
		return result
	}
	timeout := 180 * time.Second
	if !entry.Write {
		timeout = 18 * time.Second
	} // return before rpcd's read timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if entry.Write {
		finish, err := e.Host.Begin(ctx)
		if err != nil {
			result.Error = "Unable to acquire configuration transaction"
			return result
		}
		defer func() {
			if err := finish(result.OK); err != nil {
				result.OK = false
				result.Error = "Configuration transaction could not be finalized; check local recovery state"
				result.Redirect = ""
			}
		}()
	}
	L := lua.NewState(lua.Options{CallStackSize: 128, RegistrySize: 16384, RegistryMaxSize: 262144, RegistryGrowStep: 4096})
	defer L.Close()
	L.SetContext(ctx)
	documents := map[string]*Document{}
	load := func(pkg string) *Document {
		if d := documents[pkg]; d != nil {
			return d
		}
		d, err := e.Host.Load(ctx, pkg)
		if err != nil {
			if pkg == "homegate" && entry.Write {
				L.RaiseError("Unable to load configuration")
			}
			d = &Document{}
		}
		documents[pkg] = d
		return d
	}
	cursor := L.NewTable()
	push := func(value any) int { L.Push(toLua(L, value)); return 1 }
	L.SetFuncs(cursor, map[string]lua.LGFunction{
		"get_all": func(L *lua.LState) int {
			s := load(L.CheckString(2)).Find(L.CheckString(3))
			if s == nil {
				return push(nil)
			}
			m := map[string]any{".name": s.Name, ".type": s.Type}
			for k, v := range s.Values {
				m[k] = v
			}
			return push(m)
		},
		"get": func(L *lua.LState) int {
			s := load(L.CheckString(2)).Find(L.CheckString(3))
			if s == nil {
				return push(nil)
			}
			if L.GetTop() < 4 {
				return push(s.Type)
			}
			return push(s.Values[L.CheckString(4)])
		},
		"set": func(L *lua.LState) int {
			pkg, name, key := L.CheckString(2), L.CheckString(3), L.CheckString(4)
			if pkg != "homegate" || !entry.Write || !identifier.MatchString(key) {
				return push(false)
			}
			s := load(pkg).Find(name)
			if s == nil {
				return push(false)
			}
			s.Values[key] = fromLua(L.Get(5))
			return push(true)
		},
		"section": func(L *lua.LState) int {
			pkg, kind, name := L.CheckString(2), L.CheckString(3), L.CheckString(4)
			if pkg != "homegate" || !entry.Write || !identifier.MatchString(kind) || !identifier.MatchString(name) || load(pkg).Find(name) != nil {
				return push(false)
			}
			values := map[string]any{}
			if table, ok := L.Get(5).(*lua.LTable); ok {
				table.ForEach(func(k, v lua.LValue) { values[k.String()] = fromLua(v) })
			}
			load(pkg).Sections = append(load(pkg).Sections, &Section{Name: name, Type: kind, Values: values})
			return push(name)
		},
		"delete": func(L *lua.LState) int {
			pkg, name := L.CheckString(2), L.CheckString(3)
			if pkg != "homegate" || !entry.Write {
				return push(false)
			}
			d := load(pkg)
			if L.GetTop() >= 4 {
				if s := d.Find(name); s != nil {
					delete(s.Values, L.CheckString(4))
				}
			} else {
				kept := []*Section{}
				for _, s := range d.Sections {
					if s.Name != name {
						kept = append(kept, s)
					}
				}
				d.Sections = kept
			}
			return push(true)
		},
		"foreach": func(L *lua.LState) int {
			d := load(L.CheckString(2))
			kind := L.OptString(3, "")
			callback := L.CheckFunction(4)
			for i, s := range append([]*Section(nil), d.Sections...) {
				if kind != "" && s.Type != kind {
					continue
				}
				m := map[string]any{".name": s.Name, ".type": s.Type, ".index": i}
				for k, v := range s.Values {
					m[k] = v
				}
				if err := L.CallByParam(lua.P{Fn: callback, NRet: 0, Protect: true}, toLua(L, m)); err != nil {
					L.RaiseError("cursor callback failed")
				}
			}
			return 0
		},
		"commit": func(L *lua.LState) int {
			pkg := L.CheckString(2)
			if pkg != "homegate" || !entry.Write {
				return push(false)
			}
			d := load(pkg)
			if _, err := config.ParseShow(d.Show()); err != nil {
				return push(false)
			}
			return push(e.Host.Commit(ctx, d) == nil)
		},
		"revert": func(L *lua.LState) int { delete(documents, L.CheckString(2)); return push(true) },
	})
	L.PreloadModule("luci.model.uci", func(L *lua.LState) int {
		table := L.NewTable()
		table.RawSetString("cursor", L.NewFunction(func(*lua.LState) int { L.Push(cursor); return 1 }))
		L.Push(table)
		return 1
	})
	preload := func(name string, functions map[string]lua.LGFunction, values map[string]any) {
		L.PreloadModule(name, func(L *lua.LState) int {
			table := L.SetFuncs(L.NewTable(), functions)
			for k, v := range values {
				table.RawSetString(k, toLua(L, v))
			}
			L.Push(table)
			return 1
		})
	}
	// The existing bridge already acquired Begin before loading any cursor.
	// Invoke the same wrapped rules without re-entering native transport/flock.
	preload("luci.model.homegate.writer", map[string]lua.LGFunction{
		"run": func(L *lua.LState) int {
			if !entry.Write || L.CheckString(1) != request.Route {
				L.RaiseError("Invalid writer dispatch")
				return 0
			}
			fn := L.CheckFunction(2)
			if err := L.CallByParam(lua.P{Fn: fn, NRet: 0, Protect: true}); err != nil {
				L.RaiseError("Writer dispatch failed")
			}
			return 0
		},
	}, nil)
	preload("luci.http", map[string]lua.LGFunction{
		"formvalue": func(L *lua.LState) int {
			value, ok := request.Form[L.CheckString(1)]
			if !ok {
				return push(nil)
			}
			return push(value)
		},
		"redirect":        func(L *lua.LState) int { result.Redirect = L.CheckString(1); return 0 },
		"prepare_content": func(L *lua.LState) int { result.Headers["Content-Type"] = L.CheckString(1); return 0 },
		"header":          func(L *lua.LState) int { result.Headers[L.CheckString(1)] = L.CheckString(2); return 0 },
		"write": func(L *lua.LState) int {
			text := L.CheckString(1)
			if response.Len()+len(text) > 4*1024*1024 {
				L.RaiseError("response exceeds limit")
			}
			response.WriteString(text)
			return 0
		},
		"urlencode": func(L *lua.LState) int { return push(url.QueryEscape(L.CheckString(1))) },
	}, nil)
	preload("luci.dispatcher", map[string]lua.LGFunction{"build_url": func(L *lua.LState) int {
		parts := []string{}
		for i := 1; i <= L.GetTop(); i++ {
			parts = append(parts, L.CheckString(i))
		}
		return push("/cgi-bin/luci/" + strings.Join(parts, "/"))
	}}, map[string]any{"context": map[string]any{"authtoken": "rpc"}})
	preload("luci.template", map[string]lua.LGFunction{"render": func(L *lua.LState) int { result.Template = L.CheckString(1); result.Data = fromLua(L.Get(2)); return 0 }}, nil)
	preload("luci.jsonc", map[string]lua.LGFunction{"parse": func(L *lua.LState) int {
		var value any
		if json.Unmarshal([]byte(L.CheckString(1)), &value) != nil {
			return push(nil)
		}
		return push(value)
	}}, nil)
	preload("luci.sys", map[string]lua.LGFunction{
		"exec": func(L *lua.LState) int { output, _ := e.Host.Shell(ctx, L.CheckString(1)); return push(output) },
		"call": func(L *lua.LState) int {
			command := L.CheckString(1)
			if !entry.Write {
				return push(1)
			}
			_, code := e.Host.Shell(ctx, command)
			return push(code)
		},
	}, nil)
	preload("nixio.fs", map[string]lua.LGFunction{
		"stat": func(L *lua.LState) int {
			stat, err := e.Host.Stat(L.CheckString(1))
			if err != nil {
				return push(nil)
			}
			return push(stat)
		},
		"chmod": func(L *lua.LState) int {
			if !entry.Write {
				return push(false)
			}
			return push(e.Host.Chmod(L.CheckString(1), uint32(L.CheckInt(2))) == nil)
		},
	}, nil)
	ioTable := L.GetGlobal("io").(*lua.LTable)
	ioTable.RawSetString("open", L.NewFunction(func(L *lua.LState) int {
		path, mode := L.CheckString(1), L.OptString(2, "r")
		writable := strings.Contains(mode, "w") || strings.Contains(mode, "a")
		if writable && !entry.Write {
			return push(nil)
		}
		var body []byte
		var err error
		if !strings.Contains(mode, "w") {
			body, err = e.Host.Read(path)
		}
		if !writable && err != nil {
			return push(nil)
		}
		if strings.Contains(mode, "w") {
			body = nil
		}
		if writable {
			if err = e.Host.Write(path, body); err != nil {
				return push(nil)
			}
		}
		position := 0
		file := L.NewTable()
		file.RawSetString("read", L.NewFunction(func(L *lua.LState) int {
			spec := L.OptString(2, "*l")
			if position >= len(body) {
				return push(nil)
			}
			if spec == "*a" {
				text := string(body[position:])
				position = len(body)
				return push(text)
			}
			rest := body[position:]
			i := bytes.IndexByte(rest, '\n')
			if i < 0 {
				position = len(body)
				return push(string(rest))
			}
			position += i + 1
			return push(string(rest[:i]))
		}))
		file.RawSetString("write", L.NewFunction(func(L *lua.LState) int {
			if !writable {
				return push(false)
			}
			for i := 2; i <= L.GetTop(); i++ {
				body = append(body, []byte(L.CheckString(i))...)
			}
			return push(true)
		}))
		file.RawSetString("close", L.NewFunction(func(L *lua.LState) int {
			if writable {
				if e.Host.Write(path, body) != nil {
					L.RaiseError("Unable to persist private file")
				}
				return push(true)
			}
			return push(true)
		}))
		file.RawSetString("lines", L.NewFunction(func(L *lua.LState) int {
			L.Push(L.NewFunction(func(L *lua.LState) int {
				if position >= len(body) {
					return push(nil)
				}
				rest := body[position:]
				i := bytes.IndexByte(rest, '\n')
				if i < 0 {
					position = len(body)
					return push(string(rest))
				}
				position += i + 1
				return push(string(rest[:i]))
			}))
			return 1
		}))
		L.Push(file)
		return 1
	}))
	L.GetGlobal("os").(*lua.LTable).RawSetString("remove", L.NewFunction(func(L *lua.LState) int {
		if !entry.Write {
			return push(false)
		}
		return push(e.Host.Remove(L.CheckString(1)) == nil)
	}))
	source, _ := rules.ReadFile("controller.lua")
	if err := L.DoString(string(source)); err != nil {
		result.Error = "Shared configuration rules failed to initialize"
		return result
	}
	module := L.GetField(L.GetField(L.GetGlobal("luci"), "controller"), "homegate")
	function := L.GetField(module, entry.Handler)
	if err := L.CallByParam(lua.P{Fn: function, NRet: 0, Protect: true}); err != nil {
		result.Error = "HomeGate request failed"
		return result
	}
	if result.Redirect != "" {
		parsed, err := url.Parse(result.Redirect)
		if err != nil || !strings.HasPrefix(parsed.Path, "/cgi-bin/luci/admin/services/homegate/") {
			result.Error = "Invalid response redirect"
			return result
		}
		if message := parsed.Query().Get("error"); message != "" {
			result.Error = message
			return result
		}
	}
	result.OK = true
	return result
}

func toLua(L *lua.LState, value any) lua.LValue {
	switch value := value.(type) {
	case nil:
		return lua.LNil
	case string:
		return lua.LString(value)
	case bool:
		return lua.LBool(value)
	case int:
		return lua.LNumber(value)
	case int64:
		return lua.LNumber(value)
	case float64:
		return lua.LNumber(value)
	case []string:
		t := L.NewTable()
		for _, v := range value {
			t.Append(lua.LString(v))
		}
		return t
	case []any:
		t := L.NewTable()
		for _, v := range value {
			t.Append(toLua(L, v))
		}
		return t
	case map[string]any:
		t := L.NewTable()
		for k, v := range value {
			t.RawSetString(k, toLua(L, v))
		}
		return t
	default:
		return lua.LString(fmt.Sprint(value))
	}
}
func fromLua(value lua.LValue) any {
	switch value := value.(type) {
	case *lua.LNilType:
		return nil
	case lua.LString:
		return string(value)
	case lua.LBool:
		return bool(value)
	case lua.LNumber:
		return float64(value)
	case *lua.LTable:
		if value.Len() > 0 {
			items := []any{}
			for i := 1; i <= value.Len(); i++ {
				items = append(items, fromLua(value.RawGetInt(i)))
			}
			return items
		}
		items := map[string]any{}
		value.ForEach(func(k, v lua.LValue) { items[k.String()] = fromLua(v) })
		return items
	default:
		return nil
	}
}
