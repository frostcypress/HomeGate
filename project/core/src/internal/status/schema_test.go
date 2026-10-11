package status

import (
	"encoding/json"
	"testing"

	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/config"
	runtimestate "homegate.local/homegate/internal/runtime"
)

func TestReportJSONSchemaV1(t *testing.T) {
	r := Build("0.5.0", "common-runtime", config.Snapshot{Configured: true, Main: config.Main{Enabled: false}}, nil, runtimestate.Probe{}, nil)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"api_version", "ok", "version", "phase", "service"} {
		if _, ok := top[key]; !ok {
			t.Fatalf("missing top-level key %q: %s", key, data)
		}
	}
	var gotVersion int
	if err := json.Unmarshal(top["api_version"], &gotVersion); err != nil || gotVersion != api.Version {
		t.Fatalf("api_version=%d err=%v", gotVersion, err)
	}
	var svc map[string]json.RawMessage
	if err := json.Unmarshal(top["service"], &svc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"configured", "enabled", "running", "healthy"} {
		if _, ok := svc[key]; !ok {
			t.Fatalf("missing service key %q: %s", key, data)
		}
	}
}
