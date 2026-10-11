package frontend

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Section struct {
	Name   string
	Type   string
	Values map[string]any
}

type Document struct{ Sections []*Section }

var identifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,95}$`)

// UCIWords decodes uci show's shell-style quoting without invoking a shell.
func UCIWords(text string) ([]string, error) {
	var result []string
	var word strings.Builder
	quote := rune(0)
	escaped, active := false, false
	for _, c := range text {
		if escaped {
			word.WriteRune(c)
			escaped = false
			active = true
			continue
		}
		if c == '\\' && quote != '\'' {
			escaped = true
			active = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			active = true
			continue
		}
		if c == ' ' || c == '\t' {
			if active {
				result = append(result, word.String())
				word.Reset()
				active = false
			}
			continue
		}
		word.WriteRune(c)
		active = true
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("invalid UCI quoting")
	}
	if active {
		result = append(result, word.String())
	}
	return result, nil
}

func ParseDocument(text, pkg string) (*Document, error) {
	d := &Document{}
	for _, line := range strings.Split(text, "\n") {
		left, right, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(left, pkg+".") {
			continue
		}
		name, option, hasOption := strings.Cut(strings.TrimPrefix(left, pkg+"."), ".")
		values, err := UCIWords(right)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			values = []string{""}
		}
		s := d.Find(name)
		if !hasOption {
			if s == nil {
				s = &Section{Name: name, Values: map[string]any{}}
				d.Sections = append(d.Sections, s)
			}
			s.Type = values[0]
			continue
		}
		if s == nil {
			return nil, fmt.Errorf("option before section")
		}
		if len(values) == 1 {
			s.Values[option] = values[0]
		} else {
			s.Values[option] = values
		}
	}
	return d, nil
}

func (d *Document) Find(name string) *Section {
	for _, s := range d.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Show cannot distinguish one-element lists from options. Export supplies only
// the missing type information; section order and values still come from show.
func (d *Document) RestoreListTypes(export string) error {
	index := -1
	for _, line := range strings.Split(export, "\n") {
		words, err := UCIWords(strings.TrimSpace(line))
		if err != nil {
			return err
		}
		if len(words) == 0 {
			continue
		}
		if words[0] == "config" {
			index++
			continue
		}
		if words[0] != "list" || len(words) < 3 {
			continue
		}
		if index < 0 || index >= len(d.Sections) {
			return fmt.Errorf("UCI export section mismatch")
		}
		section := d.Sections[index]
		if value, ok := section.Values[words[1]].(string); ok {
			section.Values[words[1]] = []string{value}
		}
	}
	return nil
}
func quoteUCI(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func (d *Document) Text() (string, error) {
	var out strings.Builder
	for _, s := range d.Sections {
		if !identifier.MatchString(s.Name) || !identifier.MatchString(s.Type) {
			return "", fmt.Errorf("invalid section identifier")
		}
		fmt.Fprintf(&out, "config %s %s\n", s.Type, quoteUCI(s.Name))
		keys := make([]string, 0, len(s.Values))
		for key := range s.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !identifier.MatchString(key) {
				return "", fmt.Errorf("invalid option identifier")
			}
			switch value := s.Values[key].(type) {
			case []any:
				for _, item := range value {
					v, ok := item.(string)
					if !ok {
						return "", fmt.Errorf("UCI list must contain strings")
					}
					fmt.Fprintf(&out, "\tlist %s %s\n", key, quoteUCI(v))
				}
			case []string:
				for _, v := range value {
					fmt.Fprintf(&out, "\tlist %s %s\n", key, quoteUCI(v))
				}
			default:
				fmt.Fprintf(&out, "\toption %s %s\n", key, quoteUCI(fmt.Sprint(value)))
			}
		}
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func (d *Document) Show() string {
	var out strings.Builder
	for _, s := range d.Sections {
		fmt.Fprintf(&out, "homegate.%s=%s\n", s.Name, quoteUCI(s.Type))
		for key, value := range s.Values {
			fmt.Fprintf(&out, "homegate.%s.%s=", s.Name, key)
			var list []string
			switch v := value.(type) {
			case []string:
				list = v
			case []any:
				for _, item := range v {
					list = append(list, fmt.Sprint(item))
				}
			}
			if list != nil {
				for i, v := range list {
					if i != 0 {
						out.WriteByte(' ')
					}
					out.WriteString(quoteUCI(v))
				}
			} else {
				out.WriteString(quoteUCI(fmt.Sprint(value)))
			}
			out.WriteByte('\n')
		}
	}
	return out.String()
}
