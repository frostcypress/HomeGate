package network

import "homegate.local/homegate/internal/api"

const Phase = "network-resolver"

type Report struct {
	APIVersion int    `json:"api_version"`
	OK         bool   `json:"ok"`
	Version    string `json:"version"`
	Phase      string `json:"phase"`
	Network    Result `json:"network"`
	Error      string `json:"error,omitempty"`
}

func BuildReport(version string, result Result, err error) Report {
	r := Report{APIVersion: api.Version, OK: err == nil, Version: version, Phase: Phase, Network: result}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
