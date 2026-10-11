package certimport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"homegate.local/homegate/internal/certstore"
	"homegate.local/homegate/internal/runtimefile"
)

const maxPEMBytes = 512 * 1024

var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type Report struct {
	APIVersion  int      `json:"api_version"`
	OK          bool     `json:"ok"`
	Version     string   `json:"version"`
	Phase       string   `json:"phase"`
	Certificate string   `json:"certificate"`
	Domains     []string `json:"domains,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Error       string   `json:"error,omitempty"`
}

func failure(version, id string, err error) (Report, error) {
	return Report{APIVersion: 1, OK: false, Version: version, Phase: "certificate-import", Certificate: id, Error: err.Error()}, err
}

func readLimited(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() <= 0 || st.Size() > maxPEMBytes {
		return nil, fmt.Errorf("PEM file size is invalid")
	}
	return os.ReadFile(path)
}

func inspectPair(chain, key []byte, now time.Time) ([]string, time.Time, error) {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, time.Time{}, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse certificate leaf: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return nil, time.Time{}, fmt.Errorf("certificate is not valid yet")
	}
	if !now.Before(leaf.NotAfter) {
		return nil, time.Time{}, fmt.Errorf("certificate has expired")
	}
	seen := map[string]bool{}
	domains := make([]string, 0, len(leaf.DNSNames))
	for _, raw := range leaf.DNSNames {
		name, err := certstore.NormalizePattern(raw)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("certificate DNS identity: %w", err)
		}
		if !seen[name] {
			seen[name] = true
			domains = append(domains, name)
		}
	}
	if len(domains) == 0 {
		return nil, time.Time{}, fmt.Errorf("certificate has no DNS SAN identities")
	}
	sort.Strings(domains)
	return domains, leaf.NotAfter, nil
}

func restore(path string, old []byte, existed bool) error {
	if existed {
		return runtimefile.WriteAtomic(path, old, 0o600)
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Import validates a user-provided certificate/private-key pair and publishes
// it atomically into HomeGate's certificate directory. It never modifies UCI;
// the caller owns the configuration transaction that references the returned
// identities.
func Import(homeDir, version, id, certPath, keyPath string) (Report, error) {
	id = strings.TrimSpace(id)
	if id == "" || !safeIDPattern.MatchString(id) {
		return failure(version, id, fmt.Errorf("invalid certificate id"))
	}
	chain, err := readLimited(certPath)
	if err != nil {
		return failure(version, id, fmt.Errorf("read certificate: %w", err))
	}
	key, err := readLimited(keyPath)
	if err != nil {
		return failure(version, id, fmt.Errorf("read private key: %w", err))
	}
	domains, expires, err := inspectPair(chain, key, time.Now())
	if err != nil {
		return failure(version, id, err)
	}
	if strings.TrimSpace(homeDir) == "" {
		homeDir = "/etc/homegate"
	}
	dir := filepath.Join(homeDir, "certs", id)
	certDst := filepath.Join(dir, "fullchain.pem")
	keyDst := filepath.Join(dir, "privkey.pem")
	oldKey, keyErr := os.ReadFile(keyDst)
	hadKey := keyErr == nil
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return failure(version, id, fmt.Errorf("read previous private key: %w", keyErr))
	}
	if err := runtimefile.WriteAtomic(keyDst, key, 0o600); err != nil {
		return failure(version, id, fmt.Errorf("publish private key: %w", err))
	}
	if err := runtimefile.WriteAtomic(certDst, chain, 0o600); err != nil {
		rollbackErr := restore(keyDst, oldKey, hadKey)
		if rollbackErr != nil {
			return failure(version, id, fmt.Errorf("publish certificate: %v; restore previous private key: %w", err, rollbackErr))
		}
		return failure(version, id, fmt.Errorf("publish certificate: %w", err))
	}
	return Report{APIVersion: 1, OK: true, Version: version, Phase: "certificate-import", Certificate: id, Domains: domains, Expires: expires.UTC().Format(time.RFC3339)}, nil
}

// InspectPEM exposes the identity parser for controller-independent tests.
func InspectPEM(chain, key []byte, now time.Time) ([]string, time.Time, error) {
	return inspectPair(chain, key, now)
}
