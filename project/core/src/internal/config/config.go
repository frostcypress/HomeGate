package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultLogLevel               = "info"
	DefaultLogMaxLines            = 1024
	DefaultWOLInterface           = "br-lan"
	DefaultDDNSInterval           = 300
	DefaultACMEDirectory          = "https://acme-v02.api.letsencrypt.org/directory"
	StagingACMEDirectory          = "https://acme-staging-v02.api.letsencrypt.org/directory"
	CertificateEnvProduction      = "production"
	CertificateEnvStaging         = "staging"
	DefaultCertificateEnvironment = CertificateEnvProduction
	DefaultRenewDays              = 30
	DefaultHTTPSPort              = 443
	DefaultHTTPPort               = 0
	DefaultProxyHTTPSPort         = 10443
	DefaultProxyHTTPPort          = 10080
)

var ErrNoLoader = errors.New("config loader is not configured")

type Main struct {
	Enabled             bool   `json:"enabled"`
	LogLevel            string `json:"log_level"`
	LogMaxLines         int    `json:"log_max_lines"`
	LogCaptureErrors    bool   `json:"log_capture_errors"` // legacy compatibility; UI no longer exposes it
	AccessEnabled       bool   `json:"access_enabled"`
	AccessAllow         string `json:"access_allow,omitempty"`
	AccessDeny          string `json:"access_deny,omitempty"`
	AccessRegion        string `json:"access_region,omitempty"`
	RetiredAccessRegion string `json:"retired_access_region,omitempty"`
	WOLInterface        string `json:"wol_interface"`
	LastWOLHost         string `json:"last_wol_host,omitempty"`
	DDNSInterval        int    `json:"ddns_interval"`
	ACMEEmail           string `json:"acme_email,omitempty"`
	ACMEDirectory       string `json:"acme_directory"`
	RenewDays           int    `json:"renew_days"`
	HTTPSPort           int    `json:"https_port"`
	HTTPPort            int    `json:"http_port"`
	ProxyHTTPSPort      int    `json:"proxy_https_port"`
	ProxyHTTPPort       int    `json:"proxy_http_port"`
	AutoFirewall        bool   `json:"auto_firewall"`
}

type DNSAccount struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Provider  string `json:"provider"`
	KeyID     string `json:"-"`
	Secret    string `json:"-"`
	AccountID string `json:"-"`
	Endpoint  string `json:"-"`
}

type DDNSRule struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name,omitempty"`
	Account   string `json:"account"`
	Zone      string `json:"zone"`
	Host      string `json:"host"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Interface string `json:"interface,omitempty"`
	URL       string `json:"url,omitempty"`
	TTL       int    `json:"ttl"`
}

type Certificate struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Name        string   `json:"name,omitempty"`
	Source      string   `json:"source"`
	Account     string   `json:"account"`
	Zone        string   `json:"zone"`
	Domains     []string `json:"domains"`
	Email       string   `json:"email,omitempty"`
	RenewDays   int      `json:"renew_days"`
	CA          string   `json:"ca"`
	Environment string   `json:"environment"`
}

func CertificateACMEDirectory(environment string) string {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case CertificateEnvStaging:
		return StagingACMEDirectory
	default:
		return DefaultACMEDirectory
	}
}

type WOLHost struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	MAC  string `json:"mac"`
}

type WebRule struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Domain      string `json:"domain"`
	Target      string `json:"target"`
	HTTPS       bool   `json:"https"`
	Certificate string `json:"certificate,omitempty"`
}

type Snapshot struct {
	Configured   bool                  `json:"configured"`
	Main         Main                  `json:"main"`
	Accounts     map[string]DNSAccount `json:"-"`
	DDNS         []DDNSRule            `json:"-"`
	Certificates []Certificate         `json:"-"`
	Web          []WebRule             `json:"-"`
	WOL          []WOLHost             `json:"-"`
}

type Loader interface {
	Load(context.Context) (Snapshot, error)
}

type CommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type UCILoader struct {
	Runner CommandRunner
}

func NewUCILoader() UCILoader {
	return UCILoader{Runner: execRunner{}}
}

func defaults() Snapshot {
	return Snapshot{Main: Main{
		Enabled:          false,
		LogLevel:         DefaultLogLevel,
		LogMaxLines:      DefaultLogMaxLines,
		LogCaptureErrors: true,
		AccessEnabled:    false,
		WOLInterface:     DefaultWOLInterface,
		DDNSInterval:     DefaultDDNSInterval,
		ACMEDirectory:    DefaultACMEDirectory,
		RenewDays:        DefaultRenewDays,
		HTTPSPort:        DefaultHTTPSPort,
		HTTPPort:         DefaultHTTPPort,
		ProxyHTTPSPort:   DefaultProxyHTTPSPort,
		ProxyHTTPPort:    DefaultProxyHTTPPort,
		AutoFirewall:     true,
	}, Accounts: map[string]DNSAccount{}, Certificates: []Certificate{}, Web: []WebRule{}, WOL: []WOLHost{}}
}

func (l UCILoader) Load(ctx context.Context) (Snapshot, error) {
	if l.Runner == nil {
		l.Runner = execRunner{}
	}
	out, err := l.Runner.Output(ctx, "uci", "-q", "show", "homegate")
	if err != nil {
		return Snapshot{}, fmt.Errorf("read UCI homegate config: %w", err)
	}
	return ParseShow(string(out))
}

func ParseShow(text string) (Snapshot, error) {
	s := defaults()
	values := make(map[string]string)
	lists := make(map[string][]string)

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquoteUCI(strings.TrimSpace(value))
		if _, exists := values[key]; exists {
			lists[key] = append(lists[key], value)
		} else {
			values[key] = value
		}
		if key == "homegate.main" && value == "homegate" {
			s.Configured = true
		}
	}

	if !s.Configured {
		return s, errors.New("missing config homegate 'main' section")
	}

	if v, ok := values["homegate.main.enabled"]; ok {
		s.Main.Enabled = parseBool(v)
	}
	if v, ok := values["homegate.main.log_level"]; ok && v != "" {
		if !validLogLevel(v) {
			return s, fmt.Errorf("invalid log_level %q", v)
		}
		s.Main.LogLevel = v
	}
	if v, ok := values["homegate.main.log_max_lines"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 64 || n > 20000 {
			return s, fmt.Errorf("invalid log_max_lines %q", v)
		}
		s.Main.LogMaxLines = n
	}
	if v, ok := values["homegate.main.log_capture_errors"]; ok {
		s.Main.LogCaptureErrors = parseBool(v)
	}
	if v, ok := values["homegate.main.access_enabled"]; ok {
		s.Main.AccessEnabled = parseBool(v)
	}
	if v, ok := values["homegate.main.access_allow"]; ok {
		s.Main.AccessAllow = strings.TrimSpace(v)
		if err := validateAccessAllow(s.Main.AccessAllow); err != nil {
			return s, err
		}
	}
	if v, ok := values["homegate.main.access_deny"]; ok {
		s.Main.AccessDeny = strings.TrimSpace(v)
		if err := validateAccessAllow(s.Main.AccessDeny); err != nil {
			return s, fmt.Errorf("invalid access deny rule: %w", err)
		}
	}
	if v, ok := values["homegate.main.access_region"]; ok {
		s.Main.AccessRegion = strings.ToUpper(strings.TrimSpace(v))
		if s.Main.AccessRegion != "" && !validAccessRegionKey(s.Main.AccessRegion) {
			return s, fmt.Errorf("invalid access_region %q", v)
		}
		// Retired province policies must not silently become unrestricted or
		// broaden to all of CN. Preserve manual/deny rules and the enabled bit.
		if strings.HasPrefix(s.Main.AccessRegion, "CN-") {
			s.Main.RetiredAccessRegion = s.Main.AccessRegion
			s.Main.AccessRegion = ""
		} else if s.Main.AccessRegion != "" && s.Main.AccessRegion != "CN" {
			return s, fmt.Errorf("unsupported access_region %q", v)
		}
	}
	if v, ok := values["homegate.main.wol_interface"]; ok && strings.TrimSpace(v) != "" {
		s.Main.WOLInterface = strings.TrimSpace(v)
	}
	if v, ok := values["homegate.main.last_wol_host"]; ok {
		s.Main.LastWOLHost = strings.TrimSpace(v)
	}
	if v, ok := values["homegate.main.ddns_interval"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return s, fmt.Errorf("invalid ddns_interval %q", v)
		}
		if n < 60 {
			n = 60
		}
		s.Main.DDNSInterval = n
	}
	if v, ok := values["homegate.main.acme_email"]; ok {
		s.Main.ACMEEmail = strings.TrimSpace(v)
	}
	if v, ok := values["homegate.main.acme_directory"]; ok && strings.TrimSpace(v) != "" {
		s.Main.ACMEDirectory = strings.TrimSpace(v)
	}
	if v, ok := values["homegate.main.renew_days"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			return s, fmt.Errorf("invalid renew_days %q", v)
		}
		s.Main.RenewDays = n
	}
	for key, dst := range map[string]*int{
		"homegate.main.https_port":       &s.Main.HTTPSPort,
		"homegate.main.http_port":        &s.Main.HTTPPort,
		"homegate.main.proxy_https_port": &s.Main.ProxyHTTPSPort,
		"homegate.main.proxy_http_port":  &s.Main.ProxyHTTPPort,
	} {
		if raw, ok := values[key]; ok && strings.TrimSpace(raw) != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 || n > 65535 {
				return s, fmt.Errorf("invalid %s %q", strings.TrimPrefix(key, "homegate.main."), raw)
			}
			*dst = n
		}
	}
	if v, ok := values["homegate.main.auto_firewall"]; ok {
		s.Main.AutoFirewall = parseBool(v)
	}

	// Parse named r6 business sections without making their credentials part of
	// the public common-config JSON. Phase 5 consumes Aliyun AAAA/auto plus certificate/ACME fields,
	// while the parser intentionally keeps the legacy fields for later modules.
	for key, typ := range values {
		if !strings.HasPrefix(key, "homegate.") || strings.Count(key, ".") != 1 {
			continue
		}
		id := strings.TrimPrefix(key, "homegate.")
		switch typ {
		case "dns_account":
			s.Accounts[id] = DNSAccount{
				ID:        id,
				Name:      values[key+".name"],
				Provider:  strings.ToLower(strings.TrimSpace(values[key+".provider"])),
				KeyID:     values[key+".id"],
				Secret:    values[key+".secret"],
				AccountID: strings.TrimSpace(values[key+".account_id"]),
				Endpoint:  strings.TrimSpace(values[key+".endpoint"]),
			}
		case "ddns_rule":
			typ := strings.ToUpper(strings.TrimSpace(values[key+".type"]))
			if typ == "" {
				typ = "AAAA"
			}
			source := strings.ToLower(strings.TrimSpace(values[key+".source"]))
			if source == "" {
				source = "auto"
			}
			ttl := 600
			if raw := values[key+".ttl"]; raw != "" {
				if n, err := strconv.Atoi(raw); err == nil && n > 0 {
					ttl = n
				}
			}
			s.DDNS = append(s.DDNS, DDNSRule{
				ID:        id,
				Enabled:   parseBoolDefault(values[key+".enabled"], true),
				Name:      values[key+".name"],
				Account:   values[key+".account"],
				Zone:      strings.TrimSuffix(strings.ToLower(strings.TrimSpace(values[key+".zone"])), "."),
				Host:      strings.TrimSuffix(strings.ToLower(strings.TrimSpace(values[key+".host"])), "."),
				Type:      typ,
				Source:    source,
				Interface: values[key+".interface"],
				URL:       values[key+".url"],
				TTL:       ttl,
			})
		case "web_rule":
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(values[key+".domain"]), "."))
			target := strings.TrimSpace(values[key+".target"])
			enabled := parseBoolDefault(values[key+".enabled"], true)
			https := parseBoolDefault(values[key+".https"], true)
			if enabled {
				if domain == "" {
					return s, fmt.Errorf("web rule %s has empty domain", id)
				}
				u, err := url.Parse(target)
				if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
					return s, fmt.Errorf("web rule %s has invalid target %q", id, target)
				}
				if https && s.Main.ProxyHTTPSPort == 0 {
					return s, fmt.Errorf("web rule %s requires proxy_https_port", id)
				}
				if https && s.Main.ProxyHTTPPort == 0 {
					return s, fmt.Errorf("web rule %s requires proxy_http_port for HTTP-to-HTTPS redirect", id)
				}
				if !https && s.Main.ProxyHTTPPort == 0 {
					return s, fmt.Errorf("web rule %s requires proxy_http_port", id)
				}
			}
			s.Web = append(s.Web, WebRule{
				ID: id, Enabled: enabled,
				Domain: domain, Target: target, HTTPS: https,
				Certificate: strings.TrimSpace(values[key+".certificate"]),
			})
		case "wol_host":
			s.WOL = append(s.WOL, WOLHost{
				ID:   id,
				Name: strings.TrimSpace(values[key+".name"]),
				MAC:  strings.ToUpper(strings.TrimSpace(values[key+".mac"])),
			})
		case "certificate":
			domains := make([]string, 0)
			if first := strings.TrimSpace(values[key+".domain"]); first != "" {
				domains = append(domains, first)
			}
			for _, d := range lists[key+".domain"] {
				if d = strings.TrimSpace(d); d != "" {
					domains = append(domains, d)
				}
			}
			if len(domains) == 0 {
				for _, d := range strings.Split(values[key+".domains"], ",") {
					if d = strings.TrimSpace(d); d != "" {
						domains = append(domains, d)
					}
				}
			}
			renewDays := s.Main.RenewDays
			if raw := strings.TrimSpace(values[key+".renew_days"]); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil || n < 1 || n > 3650 {
					return s, fmt.Errorf("invalid certificate %s renew_days %q", id, raw)
				}
				renewDays = n
			}
			source := strings.ToLower(strings.TrimSpace(values[key+".source"]))
			if source == "" {
				source = "acme"
			}
			if source != "acme" && source != "local" {
				return s, fmt.Errorf("invalid certificate %s source %q", id, source)
			}
			ca := strings.ToLower(strings.TrimSpace(values[key+".ca"]))
			if ca == "" {
				// 1.1.0 migration rule: all pre-1.1 ACME certificates were Let's Encrypt.
				ca = "letsencrypt"
			}
			environment := strings.ToLower(strings.TrimSpace(values[key+".environment"]))
			if environment == "" {
				// Certificates created before per-resource environments existed are
				// always production certificates.
				environment = DefaultCertificateEnvironment
			}
			if environment != CertificateEnvProduction && environment != CertificateEnvStaging {
				return s, fmt.Errorf("invalid certificate %s environment %q", id, environment)
			}
			s.Certificates = append(s.Certificates, Certificate{
				ID: id, Enabled: parseBoolDefault(values[key+".enabled"], true),
				Name: values[key+".name"], Source: source, Account: values[key+".account"],
				Zone:    strings.TrimSuffix(strings.ToLower(strings.TrimSpace(values[key+".zone"])), "."),
				Domains: domains, Email: strings.TrimSpace(values[key+".email"]), RenewDays: renewDays,
				CA: ca, Environment: environment,
			})
		}
	}
	sort.Slice(s.DDNS, func(i, j int) bool { return s.DDNS[i].ID < s.DDNS[j].ID })
	sort.Slice(s.Certificates, func(i, j int) bool { return s.Certificates[i].ID < s.Certificates[j].ID })
	sort.Slice(s.Web, func(i, j int) bool { return s.Web[i].ID < s.Web[j].ID })
	sort.Slice(s.WOL, func(i, j int) bool { return s.WOL[i].ID < s.WOL[j].ID })
	seenWeb := map[string]string{}
	for _, r := range s.Web {
		if !r.Enabled {
			continue
		}
		if prev, ok := seenWeb[r.Domain]; ok {
			return s, fmt.Errorf("duplicate enabled web domain %s in %s and %s", r.Domain, prev, r.ID)
		}
		seenWeb[r.Domain] = r.ID
	}

	return s, nil
}

func parseBoolDefault(v string, def bool) bool {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return parseBool(v)
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func validateAccessAllow(raw string) error {
	raw = strings.NewReplacer("\r", ",", "\n", ",", ";", ",", "\t", ",", " ", ",").Replace(raw)
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "/") {
			if _, err := netip.ParsePrefix(token); err != nil {
				return fmt.Errorf("invalid access IP or CIDR %q", token)
			}
		} else if _, err := netip.ParseAddr(token); err != nil {
			return fmt.Errorf("invalid access IP or CIDR %q", token)
		}
	}
	return nil
}

func validAccessRegionKey(v string) bool {
	if len(v) < 2 || len(v) > 16 {
		return false
	}
	for _, r := range v {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validLogLevel(v string) bool {
	switch strings.ToLower(v) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func unquoteUCI(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, "'\\''", "'")
	}
	return v
}
