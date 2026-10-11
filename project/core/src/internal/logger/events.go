package logger

import (
	"os"
	"regexp"
	"strings"
)

type Event struct {
	Timestamp string `json:"timestamp,omitempty"`
	Level     string `json:"level"`
	Category  string `json:"category"`
	Kind      string `json:"kind"`
	Important bool   `json:"important"`
	Summary   string `json:"summary"`
	Raw       string `json:"raw"`
}

type EventsReport struct {
	APIVersion int     `json:"api_version"`
	OK         bool    `json:"ok"`
	Version    string  `json:"version"`
	Phase      string  `json:"phase"`
	Count      int     `json:"count"`
	Events     []Event `json:"events"`
}

var rawLogLineRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(DEBUG|INFO|WARN|ERROR)\] (.*)$`)

func ReadEvents(path, version string, maxLines int) EventsReport {
	if path == "" {
		path = DefaultPath
	}
	if maxLines <= 0 {
		maxLines = 1024
	}
	if maxLines > 20000 {
		maxLines = 20000
	}
	report := EventsReport{APIVersion: 1, OK: true, Version: version, Phase: "log-events", Events: []Event{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return report
		}
		report.OK = false
		return report
	}
	defer f.Close()

	lines, _, err := readTail(f, maxLines)
	if err != nil {
		report.OK = false
		return report
	}
	report.Events = make([]Event, 0, len(lines))
	for _, line := range lines {
		report.Events = append(report.Events, ParseEvent(line))
	}
	report.Count = len(report.Events)
	return report
}

func ParseEvent(raw string) Event {
	// Raw log lines have already passed Logger.Sanitize(), but sanitize again so
	// hand-written or legacy lines can never reintroduce credentials through the
	// structured view.
	raw = Sanitize(raw)
	ev := Event{Level: "INFO", Category: "system", Kind: "generic_info", Summary: "Runtime event", Raw: raw}
	message := raw
	if m := rawLogLineRE.FindStringSubmatch(raw); len(m) == 4 {
		ev.Timestamp = m[1]
		ev.Level = m[2]
		message = m[3]
	}
	lower := strings.ToLower(message)

	switch ev.Level {
	case "ERROR":
		ev.Kind = "generic_error"
		ev.Summary = "Operation failed"
		ev.Important = true
	case "WARN":
		ev.Kind = "generic_warning"
		ev.Summary = "Attention required"
		ev.Important = true
	case "DEBUG":
		ev.Kind = "generic_debug"
		ev.Summary = "Technical event"
	}

	// System lifecycle and configuration.
	if strings.Contains(message, "common runtime started") {
		setEvent(&ev, "system", "system_started", "HomeGate service started", true)
		return ev
	}
	if strings.Contains(message, "common runtime stopped") {
		setEvent(&ev, "system", "system_stopped", "HomeGate service stopped", true)
		return ev
	}
	if strings.Contains(message, "configuration reloaded") {
		setEvent(&ev, "system", "config_reloaded", "Settings applied", true)
		return ev
	}
	if strings.Contains(message, "configuration reload rejected") {
		setEvent(&ev, "system", "config_error", "Settings could not be applied", true)
		return ev
	}

	// DDNS.
	if strings.HasPrefix(message, "DDNS ") || strings.Contains(message, "DDNS recovery") || strings.Contains(message, "DDNS status") {
		if strings.Contains(lower, "unchanged") {
			setEvent(&ev, "ddns", "ddns_unchanged", "Domain address does not need updating", false)
		} else if ev.Level == "ERROR" || strings.Contains(lower, " failed") {
			setEvent(&ev, "ddns", "ddns_error", "Dynamic DNS update failed", true)
		} else if strings.Contains(lower, " deleted") {
			setEvent(&ev, "ddns", "ddns_deleted", "Dynamic DNS record deleted", true)
		} else if strings.Contains(lower, "recovery scheduled") {
			setEvent(&ev, "ddns", "ddns_recovery", "Dynamic DNS recovery scheduled", true)
		} else {
			setEvent(&ev, "ddns", "ddns_updated", "Domain address updated", true)
		}
		return ev
	}

	// Certificates / ACME.
	if strings.Contains(lower, "certificate") || strings.Contains(lower, "acme ") {
		if strings.Contains(lower, "issued/renewed") {
			setEvent(&ev, "certificate", "certificate_renewed", "Certificate issued or renewed", true)
		} else if ev.Level == "ERROR" || strings.Contains(lower, " failed") || strings.Contains(lower, "timeout") {
			setEvent(&ev, "certificate", "certificate_error", "Certificate operation failed", true)
		} else if strings.Contains(lower, "recovery scheduled") {
			setEvent(&ev, "certificate", "certificate_recovery", "Certificate recovery scheduled", true)
		} else {
			setEvent(&ev, "certificate", "certificate_ok", "Certificate status event", false)
		}
		return ev
	}

	// Access policy.
	if strings.Contains(lower, "access ") {
		if strings.Contains(lower, "denied ip=") {
			setEvent(&ev, "access", "access_denied", "Access request blocked", false)
		} else if strings.Contains(lower, "refreshed") || strings.Contains(lower, " prepared") {
			setEvent(&ev, "access", "access_updated", "Access region data updated", true)
		} else if strings.Contains(lower, "stale cache") {
			setEvent(&ev, "access", "access_cached", "Using cached access region data", true)
		} else if ev.Level == "ERROR" || ev.Level == "WARN" || strings.Contains(lower, " failed") {
			setEvent(&ev, "access", "access_error", "Access control update failed", true)
		} else if strings.Contains(lower, "recovery scheduled") {
			setEvent(&ev, "access", "access_recovery", "Access control recovery scheduled", true)
		} else {
			setEvent(&ev, "access", "access_event", "Access control event", false)
		}
		return ev
	}

	// WAN / network / WOL.
	if strings.Contains(lower, "wan ") || strings.Contains(lower, "wol ") || strings.Contains(lower, "network ") {
		if ev.Level == "ERROR" || strings.Contains(lower, " failed") {
			setEvent(&ev, "network", "network_error", "Network operation failed", true)
		} else if strings.Contains(lower, "wol sent") {
			setEvent(&ev, "network", "wol_sent", "Wake-on-LAN packet sent", true)
		} else if strings.Contains(lower, "wan reconciled") || strings.Contains(lower, "wan event") {
			setEvent(&ev, "network", "network_updated", "Public network connection updated", true)
		} else {
			setEvent(&ev, "network", "network_event", "Network event", false)
		}
		return ev
	}

	// Public service proxy / firewall.
	if strings.Contains(lower, "proxy") || strings.Contains(lower, "firewall") || strings.Contains(lower, "web https internal listener") || strings.Contains(lower, "web http internal listener") {
		if ev.Level == "ERROR" || strings.Contains(lower, " failed") || strings.Contains(lower, "unexpectedly") || strings.Contains(lower, "exhausted") {
			setEvent(&ev, "public", "public_error", "Public service runtime error", true)
		} else if strings.Contains(lower, "recovered") {
			setEvent(&ev, "public", "public_recovered", "Public service recovered", true)
		} else if strings.Contains(lower, "active") || strings.Contains(lower, "reconciled") || strings.Contains(lower, "enabled") {
			setEvent(&ev, "public", "public_ready", "Public service routing updated", true)
		} else if strings.Contains(lower, "stopped") {
			setEvent(&ev, "public", "public_stopped", "Public service listener stopped", true)
		} else if strings.Contains(lower, "recovery scheduled") {
			setEvent(&ev, "public", "public_recovery", "Public service recovery scheduled", true)
		} else {
			setEvent(&ev, "public", "public_event", "Public service event", false)
		}
		return ev
	}

	return ev
}

func setEvent(ev *Event, category, kind, summary string, important bool) {
	ev.Category = category
	ev.Kind = kind
	ev.Summary = summary
	ev.Important = important || ev.Level == "ERROR" || ev.Level == "WARN"
}
