package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"homegate.local/homegate/internal/config"
)

// Index is the immutable certificate-selection view consumed by runtime users.
// Certificate issuance/rotation remains owned by ACME; this index owns only
// identity, coverage and deterministic selection semantics.
type Index struct {
	byID      map[string]config.Certificate
	exact     map[string]string
	wildcards map[string]string
}

func NormalizeName(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

func NormalizePattern(v string) (string, error) {
	p := NormalizeName(v)
	if p == "" {
		return "", fmt.Errorf("empty certificate domain")
	}
	if strings.ContainsAny(p, " \t\r\n/") {
		return "", fmt.Errorf("invalid certificate domain %q", v)
	}
	if strings.Contains(p, "*") {
		if !strings.HasPrefix(p, "*.") || strings.Count(p, "*") != 1 || len(p) <= 2 || strings.Contains(p[2:], "*") {
			return "", fmt.Errorf("invalid certificate wildcard %q", v)
		}
	}
	return p, nil
}

// MatchesPattern follows TLS wildcard semantics used by HomeGate: a wildcard
// covers exactly one label and never the zone apex or multiple labels.
func MatchesPattern(domain, pattern string) bool {
	domain = NormalizeName(domain)
	pattern = NormalizeName(pattern)
	if domain == "" || pattern == "" {
		return false
	}
	if domain == pattern {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(domain, suffix) {
		return false
	}
	label := strings.TrimSuffix(domain, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func Covers(cert config.Certificate, domain string) bool {
	for _, raw := range cert.Domains {
		pattern, err := NormalizePattern(raw)
		if err != nil {
			continue
		}
		if MatchesPattern(domain, pattern) {
			return true
		}
	}
	return false
}

// ValidatePEMIdentities verifies that the leaf certificate DNS SAN set matches
// the configured certificate resource identities exactly after normalization.
// It intentionally compares identity patterns, not hostname coverage: a
// wildcard SAN and an exact SAN are different certificate identities.
func ValidatePEMIdentities(chain []byte, expected []string) error {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate PEM is invalid")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate leaf: %w", err)
	}

	want := make(map[string]struct{}, len(expected))
	for _, raw := range expected {
		pattern, err := NormalizePattern(raw)
		if err != nil {
			return fmt.Errorf("configured certificate identity: %w", err)
		}
		want[pattern] = struct{}{}
	}
	if len(want) == 0 {
		return fmt.Errorf("configured certificate has no DNS identities")
	}

	got := make(map[string]struct{}, len(leaf.DNSNames))
	for _, raw := range leaf.DNSNames {
		pattern, err := NormalizePattern(raw)
		if err != nil {
			return fmt.Errorf("issued certificate DNS identity: %w", err)
		}
		got[pattern] = struct{}{}
	}
	if len(got) == 0 {
		return fmt.Errorf("issued certificate has no DNS SAN identities")
	}

	for pattern := range want {
		if _, ok := got[pattern]; !ok {
			return fmt.Errorf("issued certificate is missing DNS identity %s", pattern)
		}
	}
	for pattern := range got {
		if _, ok := want[pattern]; !ok {
			return fmt.Errorf("issued certificate contains unexpected DNS identity %s", pattern)
		}
	}
	return nil
}

func New(certificates []config.Certificate) (Index, error) {
	idx := Index{
		byID:      make(map[string]config.Certificate, len(certificates)),
		exact:     map[string]string{},
		wildcards: map[string]string{},
	}

	for _, cert := range certificates {
		id := strings.TrimSpace(cert.ID)
		if id == "" {
			return Index{}, fmt.Errorf("certificate has empty id")
		}
		if _, exists := idx.byID[id]; exists {
			return Index{}, fmt.Errorf("duplicate certificate id %s", id)
		}
		idx.byID[id] = cert
		if !cert.Enabled {
			continue
		}
		if len(cert.Domains) == 0 {
			return Index{}, fmt.Errorf("enabled certificate %s has no domains", id)
		}

		seenLocal := map[string]bool{}
		for _, raw := range cert.Domains {
			pattern, err := NormalizePattern(raw)
			if err != nil {
				return Index{}, fmt.Errorf("certificate %s: %w", id, err)
			}
			if seenLocal[pattern] {
				continue
			}
			seenLocal[pattern] = true

			target := idx.exact
			if strings.HasPrefix(pattern, "*.") {
				target = idx.wildcards
			}
			if previous, exists := target[pattern]; exists && previous != id {
				return Index{}, fmt.Errorf("certificate domain %s is duplicated by %s and %s", pattern, previous, id)
			}
			target[pattern] = id
		}
	}
	return idx, nil
}

// Resolve returns the certificate ID for a Web domain. An explicit reference is
// authoritative but must point at an enabled certificate that covers the domain.
// Automatic selection always prefers an exact SAN/domain before a wildcard.
func (i Index) Resolve(explicitID, domain string) (string, error) {
	domain = NormalizeName(domain)
	if domain == "" {
		return "", fmt.Errorf("empty web domain")
	}
	if explicitID = strings.TrimSpace(explicitID); explicitID != "" {
		cert, ok := i.byID[explicitID]
		if !ok {
			return "", fmt.Errorf("certificate %s was not found", explicitID)
		}
		if !cert.Enabled {
			return "", fmt.Errorf("certificate %s is disabled", explicitID)
		}
		if !Covers(cert, domain) {
			return "", fmt.Errorf("certificate %s does not cover %s", explicitID, domain)
		}
		return explicitID, nil
	}

	if id := i.exact[domain]; id != "" {
		return id, nil
	}
	patterns := make([]string, 0, len(i.wildcards))
	for pattern := range i.wildcards {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		if MatchesPattern(domain, pattern) {
			return i.wildcards[pattern], nil
		}
	}
	return "", fmt.Errorf("no enabled certificate covers %s", domain)
}
