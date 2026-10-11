package wol

import (
	"strings"

	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/config"
)

type Host struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	MAC  string `json:"mac"`
}

type Status struct {
	APIVersion   int    `json:"api_version"`
	OK           bool   `json:"ok"`
	Version      string `json:"version"`
	Phase        string `json:"phase"`
	Interface    string `json:"interface"`
	SelectedHost string `json:"selected_host,omitempty"`
	Hosts        []Host `json:"hosts"`
	Error        string `json:"error,omitempty"`
}

type Report struct {
	APIVersion int      `json:"api_version"`
	OK         bool     `json:"ok"`
	Version    string   `json:"version"`
	Phase      string   `json:"phase"`
	Host       string   `json:"host,omitempty"`
	Name       string   `json:"name,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	Interface  string   `json:"interface,omitempty"`
	RawSent    int      `json:"raw_sent"`
	UDPSent    int      `json:"udp_sent"`
	Interfaces []string `json:"interfaces"`
	Warnings   []string `json:"warnings,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func BuildStatus(version string, cfg config.Snapshot, err error) Status {
	r := Status{
		APIVersion:   api.Version,
		OK:           err == nil,
		Version:      version,
		Phase:        Phase,
		Interface:    cfg.Main.WOLInterface,
		SelectedHost: cfg.Main.LastWOLHost,
		Hosts:        []Host{},
	}
	for _, h := range cfg.WOL {
		r.Hosts = append(r.Hosts, Host{ID: h.ID, Name: h.Name, MAC: h.MAC})
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

func BuildReport(version string, host config.WOLHost, ifname string, result SendResult, err error) Report {
	r := Report{
		APIVersion: api.Version,
		OK:         err == nil && (result.RawSent > 0 || result.UDPSent > 0),
		Version:    version,
		Phase:      Phase,
		Host:       host.ID,
		Name:       host.Name,
		MAC:        strings.ToUpper(strings.TrimSpace(host.MAC)),
		Interface:  ifname,
		RawSent:    result.RawSent,
		UDPSent:    result.UDPSent,
		Interfaces: result.Interfaces,
		Warnings:   result.Warnings,
	}
	if r.Interfaces == nil {
		r.Interfaces = []string{}
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

func FindHost(cfg config.Snapshot, id string) (config.WOLHost, error) {
	id = strings.TrimSpace(id)
	for _, h := range cfg.WOL {
		if h.ID == id {
			return h, nil
		}
	}
	return config.WOLHost{}, &HostNotFoundError{ID: id}
}

type HostNotFoundError struct{ ID string }

func (e *HostNotFoundError) Error() string { return "WOL host not found: " + e.ID }
