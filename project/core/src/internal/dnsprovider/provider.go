package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"homegate.local/homegate/internal/config"
)

// Capability is one stable DNS-provider feature understood by HomeGate.
type Capability string

const (
	CapabilityCredentialsValidation Capability = "credentials_validation"
	CapabilityDDNS                  Capability = "ddns"
	CapabilityDNS01                 Capability = "dns01"
	CapabilityZoneDiscovery         Capability = "zone_discovery"
)

// Capabilities describes which provider operations are available. Callers use
// this instead of hard-coding provider names or guessing support from concrete
// Go types.
type Capabilities struct {
	CredentialsValidation bool `json:"credentials_validation"`
	DDNS                  bool `json:"ddns"`
	DNS01                 bool `json:"dns01"`
	ZoneDiscovery         bool `json:"zone_discovery"`
}

func (c Capabilities) Names() []string {
	out := make([]string, 0, 4)
	if c.CredentialsValidation {
		out = append(out, string(CapabilityCredentialsValidation))
	}
	if c.DDNS {
		out = append(out, string(CapabilityDDNS))
	}
	if c.DNS01 {
		out = append(out, string(CapabilityDNS01))
	}
	if c.ZoneDiscovery {
		out = append(out, string(CapabilityZoneDiscovery))
	}
	return out
}

// ErrorKind is the machine-readable provider failure taxonomy. Keep these
// values stable: CLI/LuCI diagnostics may use them without parsing messages.
type ErrorKind string

const (
	ErrorTemporary          ErrorKind = "temporary"
	ErrorAuthentication     ErrorKind = "authentication"
	ErrorRateLimit          ErrorKind = "rate_limit"
	ErrorNotFound           ErrorKind = "not_found"
	ErrorInvalidZone        ErrorKind = "invalid_zone"
	ErrorPropagationPending ErrorKind = "propagation_pending"
	ErrorNetworkUnavailable ErrorKind = "network_unavailable"
	ErrorTimeout            ErrorKind = "timeout"
	ErrorContextCanceled    ErrorKind = "context_canceled"
	ErrorUnsupported        ErrorKind = "unsupported"
	ErrorInvalidRequest     ErrorKind = "invalid_request"
	ErrorUnknown            ErrorKind = "unknown"
)

// Error is a sanitized provider error. Message must never contain credentials,
// signatures, signed URLs or other secret-bearing request material.
type Error struct {
	Provider  string
	Operation string
	Kind      ErrorKind
	Code      string
	Message   string
	Retryable bool
	Cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	prefix := strings.TrimSpace(e.Provider)
	if op := strings.TrimSpace(e.Operation); op != "" {
		if prefix != "" {
			prefix += " " + op
		} else {
			prefix = op
		}
	}
	if code := strings.TrimSpace(e.Code); code != "" {
		if prefix != "" {
			prefix += " (" + code + ")"
		} else {
			prefix = code
		}
	}
	msg := strings.TrimSpace(e.Message)
	if msg == "" && e.Cause != nil {
		msg = strings.TrimSpace(e.Cause.Error())
	}
	if prefix == "" {
		if msg != "" {
			return msg
		}
		return string(e.Kind)
	}
	if msg == "" {
		return prefix
	}
	return prefix + ": " + msg
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func NewError(provider, operation string, kind ErrorKind, code, message string, retryable bool, cause error) error {
	return &Error{
		Provider: provider, Operation: operation, Kind: kind, Code: code,
		Message: message, Retryable: retryable, Cause: cause,
	}
}

// ErrorDetails extracts the stable taxonomy from an error. Generic non-provider
// errors remain "unknown" so callers never have to infer semantics from text.
func ErrorDetails(err error) (kind ErrorKind, retryable bool, code string) {
	if err == nil {
		return "", false, ""
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Kind, pe.Retryable, pe.Code
	}
	if errors.Is(err, context.Canceled) {
		return ErrorContextCanceled, false, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTimeout, true, ""
	}
	return ErrorUnknown, false, ""
}

// RecordProvider is the shared DNS record capability used by DDNS and ACME.
// Implementations must make Delete(value != "") exact-value scoped so ACME
// cleanup cannot remove unrelated TXT records.
type RecordProvider interface {
	Upsert(context.Context, string, string, string, string, int) (string, error)
	Delete(context.Context, string, string, string, string) error
}

// Provider is the Stage 7 capability contract. All concrete providers expose
// the same metadata, credential validation, record operations and zone
// discovery entry points. Unsupported operations must return ErrorUnsupported
// rather than forcing callers to inspect the provider name.
type Provider interface {
	RecordProvider
	Name() string
	Capabilities() Capabilities
	ValidateCredentials(context.Context) error
	ListZones(context.Context) ([]string, error)
}

// Factory resolves a configured DNS account into the unified provider.
type Factory func(config.DNSAccount) (Provider, error)

// RecordFactory is kept separate for DDNS/ACME unit injection: those services
// need only the record subset and should not depend on discovery/diagnostics.
type RecordFactory func(config.DNSAccount) (RecordProvider, error)

func NewRecord(account config.DNSAccount) (RecordProvider, error) {
	return New(account)
}

// FullDomain normalizes a zone/host pair without changing an already-qualified
// host. It is shared by provider requests and their DDNS/ACME callers.
func FullDomain(zone, host string) string {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || host == "@" {
		return zone
	}
	if host == zone || strings.HasSuffix(host, "."+zone) {
		return host
	}
	return host + "." + zone
}

func Unsupported(provider, operation string) error {
	return NewError(provider, operation, ErrorUnsupported, "", fmt.Sprintf("operation %s is not supported", operation), false, nil)
}
