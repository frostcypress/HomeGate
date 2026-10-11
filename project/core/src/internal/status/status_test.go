package status

import (
	"errors"
	"testing"

	"homegate.local/homegate/internal/config"
	runtimestate "homegate.local/homegate/internal/runtime"
)

func TestSemantics(t *testing.T) {
	tests := []struct {
		name       string
		configured bool
		enabled    bool
		running    bool
		wantOK     bool
	}{
		{"enabled-running", true, true, true, true},
		{"enabled-stopped", true, true, false, false},
		{"disabled-stopped", true, false, false, true},
		{"disabled-running", true, false, true, false},
		{"missing-config", false, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Build("0.5.0", "common-runtime", config.Snapshot{Configured: tt.configured, Main: config.Main{Enabled: tt.enabled}}, nil, runtimestate.Probe{Running: tt.running}, nil)
			if r.OK != tt.wantOK || r.Service.Healthy != tt.wantOK {
				t.Fatalf("report=%+v", r)
			}
		})
	}
}

func TestConfigErrorIsReported(t *testing.T) {
	r := Build("0.5.0", "common-runtime", config.Snapshot{}, errors.New("bad config"), runtimestate.Probe{}, nil)
	if r.OK || r.Error != "bad config" {
		t.Fatalf("report=%+v", r)
	}
}
