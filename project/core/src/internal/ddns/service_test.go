package ddns

import (
	"context"
	"errors"
	"testing"
	"time"

	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/dnsprovider"
	"homegate.local/homegate/internal/network"
)

type fakeResolver struct {
	wan network.WANResult
	err error
}

func (f fakeResolver) ResolveWAN(context.Context) (network.WANResult, error) { return f.wan, f.err }

type fakeProvider struct {
	op         string
	err        error
	gotValue   string
	deleteErr  error
	deleteZone string
	deleteHost string
	deleteType string
	deleteVal  string
}

func (f *fakeProvider) Upsert(_ context.Context, _, _, _, value string, _ int) (string, error) {
	f.gotValue = value
	return f.op, f.err
}
func (f *fakeProvider) Delete(_ context.Context, zone, host, typ, value string) error {
	f.deleteZone, f.deleteHost, f.deleteType, f.deleteVal = zone, host, typ, value
	return f.deleteErr
}

type fakeLog struct{ infos, errors []string }

func (l *fakeLog) Infof(format string, args ...any)  { l.infos = append(l.infos, format) }
func (l *fakeLog) Errorf(format string, args ...any) { l.errors = append(l.errors, format) }

func r6Snapshot() config.Snapshot {
	return config.Snapshot{
		Configured: true,
		Main:       config.Main{Enabled: true, DDNSInterval: 300},
		Accounts: map[string]config.DNSAccount{
			"dns_26e7f2e39793": {ID: "dns_26e7f2e39793", Provider: "aliyun", KeyID: "id", Secret: "secret"},
		},
		DDNS: []config.DDNSRule{{
			ID: "ddns_1db14129c46f", Enabled: true, Name: "test.chenos.cn", Account: "dns_26e7f2e39793",
			Zone: "chenos.cn", Host: "test", Type: "AAAA", Source: "auto", TTL: 600,
		}},
	}
}

func TestSyncR6AliyunAAAAUnchanged(t *testing.T) {
	provider := &fakeProvider{op: "unchanged"}
	svc := Service{
		Resolver: fakeResolver{wan: network.WANResult{PublicIPv6: "2409:8a55:4f0c:353::1234", Device: "pppoe-wan", Source: "public-ip"}},
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
		Now:      func() time.Time { return time.Date(2026, 9, 5, 5, 3, 55, 0, time.UTC) },
	}
	cfg := r6Snapshot()
	got := svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "unchanged" || got.Domain != "test.chenos.cn" || got.IP != "2409:8a55:4f0c:353::1234" || provider.gotValue != got.IP {
		t.Fatalf("result=%+v providerIP=%s", got, provider.gotValue)
	}
	if got.At != "2026-09-05T05:03:55Z" {
		t.Fatalf("at=%s", got.At)
	}
}

func TestSyncCreated(t *testing.T) {
	provider := &fakeProvider{op: "created"}
	svc := Service{
		Resolver: fakeResolver{wan: network.WANResult{PublicIPv6: "2001:db8::1", Device: "pppoe-wan"}},
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
	}
	cfg := r6Snapshot()
	got := svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "created" {
		t.Fatalf("result=%+v", got)
	}
}

func TestWANFailureDoesNotCallProvider(t *testing.T) {
	called := false
	svc := Service{
		Resolver: fakeResolver{err: errors.New("no public IPv6")},
		Provider: func(config.DNSAccount) (Provider, error) { called = true; return &fakeProvider{}, nil },
	}
	cfg := r6Snapshot()
	got := svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "error" || called {
		t.Fatalf("result=%+v called=%v", got, called)
	}
}

func TestPhase4RejectsUnmigratedModes(t *testing.T) {
	cfg := r6Snapshot()
	svc := Service{Resolver: fakeResolver{wan: network.WANResult{PublicIPv6: "2001:db8::1"}}}
	rule := cfg.DDNS[0]
	rule.Type = "A"
	if got := svc.SyncRule(context.Background(), cfg, rule); got.Status != "error" {
		t.Fatalf("A result=%+v", got)
	}
	rule = cfg.DDNS[0]
	rule.Source = "url"
	if got := svc.SyncRule(context.Background(), cfg, rule); got.Status != "error" {
		t.Fatalf("url result=%+v", got)
	}
}

func TestFullDomain(t *testing.T) {
	if got := FullDomain("chenos.cn", "test"); got != "test.chenos.cn" {
		t.Fatalf("got=%s", got)
	}
	if got := FullDomain("chenos.cn", "@"); got != "chenos.cn" {
		t.Fatalf("got=%s", got)
	}
}

type countingResolver struct {
	wan   network.WANResult
	err   error
	calls int
}

func (r *countingResolver) ResolveWAN(context.Context) (network.WANResult, error) {
	r.calls++
	return r.wan, r.err
}

func TestSyncAllResolvesWANOncePerCycle(t *testing.T) {
	cfg := r6Snapshot()
	r2 := cfg.DDNS[0]
	r2.ID = "ddns_2"
	r2.Name = "two.chenos.cn"
	r2.Host = "two"
	r3 := cfg.DDNS[0]
	r3.ID = "ddns_3"
	r3.Name = "three.chenos.cn"
	r3.Host = "three"
	cfg.DDNS = []config.DDNSRule{cfg.DDNS[0], r2, r3}

	resolver := &countingResolver{wan: network.WANResult{PublicIPv6: "2409:8a55:4f0c:353::1234", Device: "pppoe-wan", Source: "public-ip"}}
	provider := &fakeProvider{op: "unchanged"}
	svc := Service{
		Resolver: resolver,
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
	}
	results := svc.SyncAll(context.Background(), cfg)
	if resolver.calls != 1 {
		t.Fatalf("ResolveWAN calls=%d want=1", resolver.calls)
	}
	if len(results) != 3 {
		t.Fatalf("results=%d", len(results))
	}
	for _, result := range results {
		if result.Status != "unchanged" || result.IP != resolver.wan.PublicIPv6 {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestSyncAllDoesNotResolveWANForIneligibleRules(t *testing.T) {
	cfg := r6Snapshot()
	disabled := cfg.DDNS[0]
	disabled.Enabled = false
	unmigrated := cfg.DDNS[0]
	unmigrated.ID = "ddns_a"
	unmigrated.Type = "A"
	cfg.DDNS = []config.DDNSRule{disabled, unmigrated}

	resolver := &countingResolver{wan: network.WANResult{PublicIPv6: "2001:db8::1"}}
	svc := Service{Resolver: resolver}
	results := svc.SyncAll(context.Background(), cfg)
	if resolver.calls != 0 {
		t.Fatalf("ResolveWAN calls=%d want=0", resolver.calls)
	}
	if results[0].Status != "disabled" || results[1].Status != "error" {
		t.Fatalf("results=%+v", results)
	}
}

func TestSyncAllSharesWANFailureWithinCycle(t *testing.T) {
	cfg := r6Snapshot()
	r2 := cfg.DDNS[0]
	r2.ID = "ddns_2"
	r2.Host = "two"
	cfg.DDNS = []config.DDNSRule{cfg.DDNS[0], r2}

	resolver := &countingResolver{err: errors.New("wan unavailable")}
	svc := Service{Resolver: resolver}
	results := svc.SyncAll(context.Background(), cfg)
	if resolver.calls != 1 {
		t.Fatalf("ResolveWAN calls=%d want=1", resolver.calls)
	}
	for _, result := range results {
		if result.Status != "error" || result.Message != "resolve public IPv6: wan unavailable" {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestSyncRuleStillResolvesWANPerManualCall(t *testing.T) {
	cfg := r6Snapshot()
	resolver := &countingResolver{wan: network.WANResult{PublicIPv6: "2001:db8::1"}}
	provider := &fakeProvider{op: "unchanged"}
	svc := Service{
		Resolver: resolver,
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
	}
	_ = svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	_ = svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if resolver.calls != 2 {
		t.Fatalf("ResolveWAN calls=%d want=2", resolver.calls)
	}
}

func TestDeleteRuleDeletesManagedHostTypeWithoutWANLookup(t *testing.T) {
	cfg := r6Snapshot()
	resolver := &countingResolver{err: errors.New("WAN should not be used")}
	provider := &fakeProvider{}
	svc := Service{
		Resolver: resolver,
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
		Now:      func() time.Time { return time.Date(2026, 9, 10, 16, 0, 0, 0, time.UTC) },
	}
	got := svc.DeleteRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "deleted" || got.Domain != "test.chenos.cn" {
		t.Fatalf("result=%+v", got)
	}
	if resolver.calls != 0 {
		t.Fatalf("ResolveWAN calls=%d want=0", resolver.calls)
	}
	if provider.deleteZone != "chenos.cn" || provider.deleteHost != "test" || provider.deleteType != "AAAA" || provider.deleteVal != "" {
		t.Fatalf("delete args zone=%q host=%q type=%q value=%q", provider.deleteZone, provider.deleteHost, provider.deleteType, provider.deleteVal)
	}
}

func TestDeleteRuleReportsProviderFailure(t *testing.T) {
	cfg := r6Snapshot()
	provider := &fakeProvider{deleteErr: errors.New("delete failed")}
	svc := Service{Provider: func(config.DNSAccount) (Provider, error) { return provider, nil }}
	got := svc.DeleteRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "error" || got.Message != "delete failed" {
		t.Fatalf("result=%+v", got)
	}
}

func TestSyncCanceledWorkDoesNotLogOperationalError(t *testing.T) {
	cfg := r6Snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	log := &fakeLog{}
	svc := Service{
		Resolver: fakeResolver{err: context.Canceled},
		Log:      log,
	}
	got := svc.SyncRule(ctx, cfg, cfg.DDNS[0])
	if got.Status != "error" {
		t.Fatalf("result=%+v", got)
	}
	if len(log.errors) != 0 {
		t.Fatalf("canceled stale work logged operational errors: %+v", log.errors)
	}
}

func TestSyncProviderErrorCarriesTaxonomy(t *testing.T) {
	provider := &fakeProvider{err: dnsprovider.NewError("aliyun", "records.list", dnsprovider.ErrorRateLimit, "Throttling.User", "slow down", true, nil)}
	svc := Service{
		Resolver: fakeResolver{wan: network.WANResult{PublicIPv6: "2001:db8::1"}},
		Provider: func(config.DNSAccount) (Provider, error) { return provider, nil },
	}
	cfg := r6Snapshot()
	got := svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "error" || got.ErrorKind != "rate_limit" || !got.Retryable || got.ProviderCode != "Throttling.User" {
		t.Fatalf("result=%+v", got)
	}
}

func TestWANFailureIsRetryableNetworkUnavailable(t *testing.T) {
	cfg := r6Snapshot()
	svc := Service{Resolver: fakeResolver{err: errors.New("WAN temporarily unavailable")}}
	got := svc.SyncRule(context.Background(), cfg, cfg.DDNS[0])
	if got.Status != "error" || got.ErrorKind != string(dnsprovider.ErrorNetworkUnavailable) || !got.Retryable {
		t.Fatalf("result=%+v", got)
	}
}

func TestCanceledWANFailureIsNotRetryable(t *testing.T) {
	cfg := r6Snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc := Service{Resolver: fakeResolver{err: context.Canceled}}
	got := svc.SyncRule(ctx, cfg, cfg.DDNS[0])
	if got.Status != "error" || got.ErrorKind != string(dnsprovider.ErrorContextCanceled) || got.Retryable {
		t.Fatalf("result=%+v", got)
	}
}

func TestInvalidRuleIsPermanentInvalidRequest(t *testing.T) {
	cfg := r6Snapshot()
	rule := cfg.DDNS[0]
	rule.Type = "A"
	svc := Service{}
	got := svc.SyncRule(context.Background(), cfg, rule)
	if got.Status != "error" || got.ErrorKind != string(dnsprovider.ErrorInvalidRequest) || got.Retryable {
		t.Fatalf("result=%+v", got)
	}
}
