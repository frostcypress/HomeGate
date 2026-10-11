package status

import (
	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/config"
	runtimestate "homegate.local/homegate/internal/runtime"
)

type Service struct {
	Configured bool `json:"configured"`
	Enabled    bool `json:"enabled"`
	Running    bool `json:"running"`
	Healthy    bool `json:"healthy"`
}

type Report struct {
	APIVersion int                 `json:"api_version"`
	OK         bool                `json:"ok"`
	Version    string              `json:"version"`
	Phase      string              `json:"phase"`
	Service    Service             `json:"service"`
	Runtime    *runtimestate.State `json:"runtime,omitempty"`
	Error      string              `json:"error,omitempty"`
}

func Build(version, phase string, cfg config.Snapshot, cfgErr error, probe runtimestate.Probe, probeErr error) Report {
	report := Report{APIVersion: api.Version, Version: version, Phase: phase}
	report.Service.Configured = cfg.Configured && cfgErr == nil
	report.Service.Enabled = cfg.Main.Enabled
	report.Service.Running = probe.Running && probeErr == nil
	report.Runtime = probe.State

	switch {
	case cfgErr != nil:
		report.Error = cfgErr.Error()
	case probeErr != nil:
		report.Error = probeErr.Error()
	}

	report.Service.Healthy = report.Service.Configured && report.Error == "" && report.Service.Enabled == report.Service.Running
	report.OK = report.Service.Healthy
	return report
}
