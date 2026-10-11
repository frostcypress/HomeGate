package acme

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"homegate.local/homegate/internal/acmeca"
)

// ProbeResult is a non-mutating ACME directory reachability result. It never
// creates an ACME account or touches account/certificate state.
type ProbeResult struct {
	CA          string
	Environment string
	Directory   string
}

func probeDirectory(ctx context.Context, directoryURL string, h HTTPDoer) error {
	if h == nil {
		h = defaultHTTPClient()
	}
	var d directory
	if err := requestJSON(ctx, h, http.MethodGet, strings.TrimSpace(directoryURL), &d); err != nil {
		return err
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return errors.New("ACME directory is incomplete")
	}
	return nil
}

// ProbeCA resolves one of HomeGate's built-in CA presets and performs a direct
// directory GET using the same proxy-disabled transport as real issuance.
func ProbeCA(ctx context.Context, ca, environment string) (ProbeResult, error) {
	sel, err := acmeca.Resolve(ca, environment)
	if err != nil {
		return ProbeResult{}, err
	}
	result := ProbeResult{CA: sel.CA, Environment: sel.Environment, Directory: sel.Directory}
	if err := probeDirectory(ctx, sel.Directory, nil); err != nil {
		return result, err
	}
	return result, nil
}
