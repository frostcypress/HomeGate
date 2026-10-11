package ddns

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/runtimefile"
)

const DefaultStatusPath = "/var/run/homegate/ddns.json"

type Report struct {
	APIVersion      int      `json:"api_version"`
	OK              bool     `json:"ok"`
	Version         string   `json:"version"`
	Phase           string   `json:"phase"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
	IntervalSeconds int      `json:"interval_seconds"`
	Results         []Result `json:"results"`
	Error           string   `json:"error,omitempty"`
}

type Store struct{ Path string }

func (s Store) path() string {
	if s.Path != "" {
		return s.Path
	}
	return DefaultStatusPath
}

func BuildReport(version string, intervalSeconds int, results []Result) Report {
	if results == nil {
		results = []Result{}
	}
	r := Report{APIVersion: api.Version, OK: ResultsOK(results), Version: version, Phase: "ddns", IntervalSeconds: intervalSeconds, Results: results}
	if len(results) > 0 {
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if !r.OK {
		r.Error = "one or more DDNS rules failed"
	}
	return r
}

func (s Store) Write(report Report) error {
	return runtimefile.WriteJSONAtomic(s.path(), report, 0o644)
}

func (s Store) Read() (Report, error) {
	var r Report
	b, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, ErrNoStatus
		}
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Results == nil {
		r.Results = []Result{}
	}
	return r, nil
}
