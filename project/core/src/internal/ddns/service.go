package ddns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/dnsprovider"
	"homegate.local/homegate/internal/network"
)

type WANResolver interface {
	ResolveWAN(context.Context) (network.WANResult, error)
}

type Provider = dnsprovider.RecordProvider

type ProviderFactory = dnsprovider.RecordFactory

type Logger interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

type Result struct {
	Rule         string `json:"rule"`
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	IP           string `json:"ip,omitempty"`
	Status       string `json:"status"`
	Message      string `json:"message,omitempty"`
	ErrorKind    string `json:"error_kind,omitempty"`
	Retryable    bool   `json:"retryable,omitempty"`
	ProviderCode string `json:"provider_code,omitempty"`
	At           string `json:"at"`
}

type Service struct {
	Resolver WANResolver
	Provider ProviderFactory
	Log      Logger
	Now      func() time.Time
}

func NewService(resolver WANResolver, log Logger) Service {
	return Service{Resolver: resolver, Provider: dnsprovider.NewRecord, Log: log, Now: time.Now}
}

func setSimpleResultError(res *Result, kind dnsprovider.ErrorKind, retryable bool) {
	if res == nil {
		return
	}
	if kind != "" && kind != dnsprovider.ErrorUnknown {
		res.ErrorKind = string(kind)
	}
	res.Retryable = retryable
}

func setResolverResultError(res *Result, ctx context.Context, err error) {
	switch {
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		setSimpleResultError(res, dnsprovider.ErrorContextCanceled, false)
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		setSimpleResultError(res, dnsprovider.ErrorTimeout, true)
	default:
		setSimpleResultError(res, dnsprovider.ErrorNetworkUnavailable, true)
	}
}

func (s Service) SyncRule(ctx context.Context, cfg config.Snapshot, rule config.DDNSRule) Result {
	return s.syncRule(ctx, cfg, rule, s.resolveWAN)
}

func (s Service) resolveWAN(ctx context.Context) (network.WANResult, error) {
	if s.Resolver == nil {
		return network.WANResult{}, errors.New("WAN resolver is not configured")
	}
	return s.Resolver.ResolveWAN(ctx)
}

func (s Service) syncRule(ctx context.Context, cfg config.Snapshot, rule config.DDNSRule, resolveWAN func(context.Context) (network.WANResult, error)) Result {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	res := Result{
		Rule:   rule.ID,
		Name:   rule.Name,
		Domain: FullDomain(rule.Zone, rule.Host),
		At:     now().UTC().Format(time.RFC3339),
	}
	if res.Name == "" {
		res.Name = res.Domain
	}

	finish := func(status, message string) Result {
		res.Status, res.Message = status, message
		if s.Log != nil {
			switch status {
			case "created", "updated":
				s.Log.Infof("DDNS %s -> %s (%s)", res.Domain, res.IP, status)
			case "error":
				// Generation changes and daemon shutdown intentionally cancel stale
				// work.  Keep the result for the caller, but do not turn expected
				// scheduler cancellation into an operational ERROR log.
				if ctx.Err() == nil {
					s.Log.Errorf("DDNS %s: %s", res.Domain, message)
				}
			}
		}
		return res
	}

	if !rule.Enabled {
		return finish("disabled", "")
	}
	if rule.Type != "AAAA" {
		setSimpleResultError(&res, dnsprovider.ErrorInvalidRequest, false)
		return finish("error", fmt.Sprintf("record type %s is not migrated in Phase 4", rule.Type))
	}
	if rule.Source != "auto" {
		setSimpleResultError(&res, dnsprovider.ErrorInvalidRequest, false)
		return finish("error", fmt.Sprintf("IP source %s is not migrated in Phase 4", rule.Source))
	}
	if strings.TrimSpace(rule.Zone) == "" {
		setSimpleResultError(&res, dnsprovider.ErrorInvalidRequest, false)
		return finish("error", "DDNS zone is empty")
	}
	account, ok := cfg.Accounts[rule.Account]
	if !ok {
		setSimpleResultError(&res, dnsprovider.ErrorNotFound, false)
		return finish("error", "DNS account not found: "+rule.Account)
	}
	wan, err := resolveWAN(ctx)
	if err != nil {
		setResolverResultError(&res, ctx, err)
		return finish("error", "resolve public IPv6: "+err.Error())
	}
	if wan.PublicIPv6 == "" {
		setSimpleResultError(&res, dnsprovider.ErrorNetworkUnavailable, true)
		return finish("error", "resolve public IPv6: empty result")
	}
	res.IP = wan.PublicIPv6

	factory := s.Provider
	if factory == nil {
		factory = dnsprovider.NewRecord
	}
	provider, err := factory(account)
	if err != nil {
		setProviderResultError(&res, err)
		return finish("error", err.Error())
	}
	operation, err := provider.Upsert(ctx, rule.Zone, rule.Host, rule.Type, res.IP, rule.TTL)
	if err != nil {
		setProviderResultError(&res, err)
		return finish("error", err.Error())
	}
	switch operation {
	case "created", "updated", "unchanged":
		return finish(operation, "")
	default:
		setSimpleResultError(&res, dnsprovider.ErrorInvalidRequest, false)
		return finish("error", "provider returned invalid operation: "+operation)
	}
}

func (s Service) DeleteRule(ctx context.Context, cfg config.Snapshot, rule config.DDNSRule) Result {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	res := Result{
		Rule:   rule.ID,
		Name:   rule.Name,
		Domain: FullDomain(rule.Zone, rule.Host),
		At:     now().UTC().Format(time.RFC3339),
	}
	if res.Name == "" {
		res.Name = res.Domain
	}
	finish := func(status, message string) Result {
		res.Status, res.Message = status, message
		if s.Log != nil {
			if status == "deleted" {
				s.Log.Infof("DDNS %s deleted", res.Domain)
			} else if status == "error" {
				s.Log.Errorf("DDNS delete %s: %s", res.Domain, message)
			}
		}
		return res
	}

	if rule.Type != "AAAA" {
		return finish("error", fmt.Sprintf("record type %s is not migrated in Phase 4", rule.Type))
	}
	if rule.Source != "auto" {
		return finish("error", fmt.Sprintf("IP source %s is not migrated in Phase 4", rule.Source))
	}
	if strings.TrimSpace(rule.Zone) == "" {
		return finish("error", "DDNS zone is empty")
	}
	account, ok := cfg.Accounts[rule.Account]
	if !ok {
		return finish("error", "DNS account not found: "+rule.Account)
	}
	factory := s.Provider
	if factory == nil {
		factory = dnsprovider.NewRecord
	}
	provider, err := factory(account)
	if err != nil {
		setProviderResultError(&res, err)
		return finish("error", err.Error())
	}
	// The DDNS hostname is owned by this HomeGate service.  Delete all records
	// of the managed type for that exact host; this avoids depending on the
	// current WAN address during teardown and leaves unrelated record types
	// (including ACME TXT) untouched.
	if err := provider.Delete(ctx, rule.Zone, rule.Host, rule.Type, ""); err != nil {
		setProviderResultError(&res, err)
		return finish("error", err.Error())
	}
	return finish("deleted", "")
}

func setProviderResultError(res *Result, err error) {
	if res == nil || err == nil {
		return
	}
	kind, retryable, code := dnsprovider.ErrorDetails(err)
	if kind != "" && kind != dnsprovider.ErrorUnknown {
		res.ErrorKind = string(kind)
	}
	res.Retryable = retryable
	res.ProviderCode = code
}

func (s Service) SyncAll(ctx context.Context, cfg config.Snapshot) []Result {
	out := make([]Result, 0, len(cfg.DDNS))
	var (
		wanResolved bool
		wan         network.WANResult
		wanErr      error
	)
	resolveWAN := func(ctx context.Context) (network.WANResult, error) {
		if !wanResolved {
			wanResolved = true
			wan, wanErr = s.resolveWAN(ctx)
		}
		return wan, wanErr
	}
	for _, rule := range cfg.DDNS {
		out = append(out, s.syncRule(ctx, cfg, rule, resolveWAN))
	}
	return out
}

func FindRule(cfg config.Snapshot, id string) (config.DDNSRule, error) {
	for _, rule := range cfg.DDNS {
		if rule.ID == id {
			return rule, nil
		}
	}
	return config.DDNSRule{}, fmt.Errorf("DDNS rule not found: %s", id)
}

func FullDomain(zone, host string) string { return dnsprovider.FullDomain(zone, host) }

func ResultsOK(results []Result) bool {
	for _, r := range results {
		if r.Status == "error" {
			return false
		}
	}
	return true
}

var ErrNoStatus = errors.New("DDNS status is not available")
