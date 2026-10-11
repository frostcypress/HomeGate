package frontend

import (
	"context"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/dnsprovider"
	"os"
	"strings"
	"time"
)

// PrivateDNSCheck performs read-only authentication/zone discovery. It emits
// only classified failures and counts; no credential values or remote body.
func PrivateDNSCheck(ctx context.Context, path string) map[string]any {
	report := map[string]any{"api_version": 1, "ok": false, "scope": "live-read-only", "operation": "DNS authentication and zone discovery"}
	request, err := ReadRequest(path)
	if err != nil {
		// The automatic shell verifier uses five private lines, avoiding a JSON
		// dependency and keeping credentials out of process arguments and logs.
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
			report["error_kind"] = "invalid_private_input"
			return report
		}
		body, readErr := os.ReadFile(path)
		fields := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
		if readErr != nil || len(fields) != 5 || strings.ContainsRune(string(body), 0) {
			report["error_kind"] = "invalid_private_input"
			return report
		}
		request.Form = map[string]string{"provider": fields[0], "key_id": fields[1], "secret": fields[2], "account_id": fields[3], "endpoint": fields[4]}
	}
	f := request.Form
	account := config.DNSAccount{ID: "offline_probe", Provider: f["provider"], KeyID: f["key_id"], Secret: f["secret"], AccountID: f["account_id"], Endpoint: f["endpoint"]}
	provider, err := dnsprovider.New(account)
	if err != nil {
		report["error_kind"] = "invalid_credentials_shape"
		return report
	}
	report["provider"] = provider.Name()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	zones, err := provider.ListZones(ctx)
	if err != nil {
		kind, retryable, _ := dnsprovider.ErrorDetails(err)
		report["error_kind"] = kind
		report["retryable"] = retryable
		return report
	}
	report["ok"] = true
	report["zone_count"] = len(zones)
	return report
}
