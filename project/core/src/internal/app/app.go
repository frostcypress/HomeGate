package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"homegate.local/homegate/internal/access"
	"homegate.local/homegate/internal/acme"
	"homegate.local/homegate/internal/acmeca"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/ddns"
	"homegate.local/homegate/internal/dnsprovider"
	"homegate.local/homegate/internal/firewall"
	"homegate.local/homegate/internal/logger"
	"homegate.local/homegate/internal/network"
	"homegate.local/homegate/internal/proxy"
	"homegate.local/homegate/internal/recovery"
	runtimestate "homegate.local/homegate/internal/runtime"
	"homegate.local/homegate/internal/scheduler"
	"homegate.local/homegate/internal/status"
	"homegate.local/homegate/internal/wol"
)

const Phase = "common-runtime"

var firewallRetryDelays = []time.Duration{
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
}

var ddnsRecoveryDelays = []time.Duration{
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
}

var acmeRecoveryDelays = []time.Duration{
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
	300 * time.Second,
}

var accessRecoveryDelays = []time.Duration{
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
}

var proxyRecoveryDelays = []time.Duration{
	2 * time.Second,
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

type App struct {
	Version         string
	Config          *config.Manager
	Runtime         runtimestate.Store
	LogPath         string
	Network         network.Resolver
	DDNSStatus      ddns.Store
	Recovery        recovery.Store
	DDNSProvider    ddns.ProviderFactory
	ACMERenewDue    func(context.Context, string, config.Snapshot) acme.RenewReport
	AccessUpdater   func(context.Context, string) (access.UpdateReport, error)
	HomeDir         string
	Firewall        firewall.Controller
	ProxyStatusPath string
	DaemonLockPath  string
	WOLSender       wol.Transport
}

func New(version string) App {
	runtimePath := os.Getenv("HOMEGATE_RUNTIME_STATE")
	logPath := os.Getenv("HOMEGATE_LOG_PATH")
	ddnsStatusPath := os.Getenv("HOMEGATE_DDNS_STATUS")
	recoveryStatusPath := os.Getenv("HOMEGATE_RECOVERY_STATUS")
	if recoveryStatusPath == "" {
		if runtimePath != "" {
			recoveryStatusPath = filepath.Join(filepath.Dir(runtimePath), "recovery.json")
		} else {
			recoveryStatusPath = recovery.DefaultStatusPath
		}
	}
	proxyStatusPath := os.Getenv("HOMEGATE_PROXY_STATUS")
	daemonLockPath := os.Getenv("HOMEGATE_DAEMON_LOCK")
	homeDir := os.Getenv("HOMEGATE_HOME_DIR")
	if homeDir == "" {
		homeDir = "/etc/homegate"
	}
	netResolver := network.New(network.ExecRunner{})
	if sysClassNet := os.Getenv("HOMEGATE_SYS_CLASS_NET"); sysClassNet != "" {
		netResolver.SysClassNet = sysClassNet
	}
	fw := firewall.New(netResolver)
	if path := os.Getenv("HOMEGATE_FIREWALL_STATUS"); path != "" {
		fw.StatusPath = path
	}
	if path := os.Getenv("HOMEGATE_FIREWALL_COMPAT_STATUS"); path != "" {
		fw.CompatStatusPath = path
	}
	return App{
		Version:         version,
		Config:          config.NewManager(config.NewUCILoader()),
		Runtime:         runtimestate.Store{Path: runtimePath},
		LogPath:         logPath,
		Network:         netResolver,
		DDNSStatus:      ddns.Store{Path: ddnsStatusPath},
		Recovery:        recovery.Store{Path: recoveryStatusPath},
		HomeDir:         homeDir,
		Firewall:        fw,
		ProxyStatusPath: proxyStatusPath,
		DaemonLockPath:  daemonLockPath,
		WOLSender:       wol.Sender{},
	}
}

func (a App) Status(ctx context.Context) status.Report {
	cfg, cfgErr := a.Config.Reload(ctx)
	probe, probeErr := a.Runtime.Probe()
	return status.Build(a.Version, Phase, cfg, cfgErr, probe, probeErr)
}

func (a App) NetworkStatus(ctx context.Context) network.Report {
	cfg, cfgErr := a.Config.Reload(ctx)
	if cfgErr != nil {
		return network.BuildReport(a.Version, network.Result{LAN: network.LANResult{Bridge: config.DefaultWOLInterface, Members: []string{}}}, cfgErr)
	}
	result, err := a.Network.Resolve(ctx, cfg.Main.WOLInterface)
	return network.BuildReport(a.Version, result, err)
}

type DNSProviderCatalogReport struct {
	APIVersion int                      `json:"api_version"`
	OK         bool                     `json:"ok"`
	Version    string                   `json:"version"`
	Phase      string                   `json:"phase"`
	Providers  []dnsprovider.Definition `json:"providers"`
}

func (a App) DNSProviderCatalog() DNSProviderCatalogReport {
	return DNSProviderCatalogReport{APIVersion: 1, OK: true, Version: a.Version, Phase: "dns-provider", Providers: dnsprovider.Definitions()}
}

type ACMECACatalogReport struct {
	APIVersion int             `json:"api_version"`
	OK         bool            `json:"ok"`
	Version    string          `json:"version"`
	Phase      string          `json:"phase"`
	CAs        []acmeca.Preset `json:"cas"`
}

func (a App) ACMECACatalog() ACMECACatalogReport {
	return ACMECACatalogReport{APIVersion: 1, OK: true, Version: a.Version, Phase: "acme-ca", CAs: acmeca.Presets()}
}

type ACMECACheckReport struct {
	APIVersion  int    `json:"api_version"`
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	Phase       string `json:"phase"`
	CA          string `json:"ca,omitempty"`
	Environment string `json:"environment,omitempty"`
	Directory   string `json:"directory,omitempty"`
	Direct      bool   `json:"direct"`
	Reachable   bool   `json:"reachable"`
	Error       string `json:"error,omitempty"`
}

func (a App) ACMECACheck(ctx context.Context, ca, environment string) (ACMECACheckReport, error) {
	report := ACMECACheckReport{APIVersion: 1, OK: false, Version: a.Version, Phase: "acme-ca", Direct: true}
	result, err := acme.ProbeCA(ctx, ca, environment)
	report.CA = result.CA
	report.Environment = result.Environment
	report.Directory = result.Directory
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.OK = true
	report.Reachable = true
	return report, nil
}

type DNSZonesReport struct {
	APIVersion   int      `json:"api_version"`
	OK           bool     `json:"ok"`
	Version      string   `json:"version"`
	Phase        string   `json:"phase"`
	Account      string   `json:"account"`
	Provider     string   `json:"provider,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Zones        []string `json:"zones"`
	Error        string   `json:"error,omitempty"`
	ErrorKind    string   `json:"error_kind,omitempty"`
	Retryable    bool     `json:"retryable,omitempty"`
	ProviderCode string   `json:"provider_code,omitempty"`
}

func setProviderError(err error, message *string, kind *string, retryable *bool, code *string) {
	if err == nil {
		return
	}
	*message = err.Error()
	k, r, c := dnsprovider.ErrorDetails(err)
	if k != "" && k != dnsprovider.ErrorUnknown {
		*kind = string(k)
	}
	*retryable = r
	*code = c
}

func (a App) DNSZones(ctx context.Context, accountID string) (DNSZonesReport, error) {
	report := DNSZonesReport{APIVersion: 1, OK: false, Version: a.Version, Phase: "dns-provider", Account: strings.TrimSpace(accountID), Zones: []string{}}
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	account, ok := cfg.Accounts[report.Account]
	if !ok {
		err = dnsprovider.NewError("", "account.resolve", dnsprovider.ErrorNotFound, "", fmt.Sprintf("DNS account not found: %s", report.Account), false, nil)
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	provider, err := dnsprovider.New(account)
	if err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	report.Provider = provider.Name()
	report.Capabilities = provider.Capabilities().Names()
	if !provider.Capabilities().ZoneDiscovery {
		err = dnsprovider.Unsupported(provider.Name(), "zones.list")
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	zones, err := provider.ListZones(ctx)
	if err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	report.OK = true
	report.Zones = zones
	return report, nil
}

type DNSProviderReport struct {
	APIVersion       int      `json:"api_version"`
	OK               bool     `json:"ok"`
	Version          string   `json:"version"`
	Phase            string   `json:"phase"`
	Account          string   `json:"account"`
	Provider         string   `json:"provider,omitempty"`
	Capabilities     []string `json:"capabilities"`
	CredentialsValid bool     `json:"credentials_valid"`
	Error            string   `json:"error,omitempty"`
	ErrorKind        string   `json:"error_kind,omitempty"`
	Retryable        bool     `json:"retryable,omitempty"`
	ProviderCode     string   `json:"provider_code,omitempty"`
}

// DNSProviderStatus exposes the Stage 7 provider contract without returning
// any credentials. Validation is read-only and provider-specific.
func (a App) DNSProviderStatus(ctx context.Context, accountID string) (DNSProviderReport, error) {
	report := DNSProviderReport{
		APIVersion: 1, OK: false, Version: a.Version, Phase: "dns-provider",
		Account: strings.TrimSpace(accountID), Capabilities: []string{},
	}
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	account, ok := cfg.Accounts[report.Account]
	if !ok {
		err = dnsprovider.NewError("", "account.resolve", dnsprovider.ErrorNotFound, "", fmt.Sprintf("DNS account not found: %s", report.Account), false, nil)
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	provider, err := dnsprovider.New(account)
	if err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	report.Provider = provider.Name()
	report.Capabilities = provider.Capabilities().Names()
	if !provider.Capabilities().CredentialsValidation {
		err = dnsprovider.Unsupported(provider.Name(), "credentials.validate")
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	if err := provider.ValidateCredentials(ctx); err != nil {
		setProviderError(err, &report.Error, &report.ErrorKind, &report.Retryable, &report.ProviderCode)
		return report, err
	}
	report.OK = true
	report.CredentialsValid = true
	return report, nil
}

func (a App) newLogger(cfg config.Snapshot) *logger.Logger {
	return logger.New(cfg.Main.LogLevel, a.LogPath, cfg.Main.LogMaxLines)
}

func (a App) newDDNS(log ddns.Logger) ddns.Service {
	service := ddns.NewService(a.Network, log)
	if a.DDNSProvider != nil {
		service.Provider = a.DDNSProvider
	}
	return service
}

func (a App) RecoveryStatus() recovery.Report { return a.Recovery.Read(a.Version) }

func (a App) runDDNSCycle(ctx context.Context, cfg config.Snapshot, log *logger.Logger) ddns.Report {
	cycleCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	service := a.newDDNS(log)
	return ddns.BuildReport(a.Version, cfg.Main.DDNSInterval, service.SyncAll(cycleCtx, cfg))
}

func (a App) SyncDDNS(ctx context.Context, ruleID string) (ddns.Report, error) {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return ddns.Report{}, err
	}
	log := a.newLogger(cfg)
	service := a.newDDNS(log)
	syncCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	var results []ddns.Result
	if ruleID == "" {
		results = service.SyncAll(syncCtx, cfg)
	} else {
		rule, findErr := ddns.FindRule(cfg, ruleID)
		if findErr != nil {
			return ddns.Report{}, findErr
		}
		results = []ddns.Result{service.SyncRule(syncCtx, cfg, rule)}
	}
	report := ddns.BuildReport(a.Version, cfg.Main.DDNSInterval, results)
	if err := a.DDNSStatus.Write(report); err != nil {
		return report, err
	}
	if !report.OK {
		return report, errors.New(report.Error)
	}
	return report, nil
}

func (a App) DeleteDDNS(ctx context.Context, ruleID string) (ddns.Report, error) {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return ddns.Report{}, err
	}
	rule, err := ddns.FindRule(cfg, ruleID)
	if err != nil {
		return ddns.Report{}, err
	}
	log := a.newLogger(cfg)
	service := a.newDDNS(log)
	deleteCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	result := service.DeleteRule(deleteCtx, cfg, rule)
	report := ddns.BuildReport(a.Version, cfg.Main.DDNSInterval, []ddns.Result{result})
	if !report.OK {
		return report, errors.New(report.Error)
	}
	return report, nil
}

func (a App) DDNSReport() ddns.Report {
	report, err := a.DDNSStatus.Read()
	if err == nil {
		return report
	}
	if errors.Is(err, ddns.ErrNoStatus) {
		return ddns.Report{APIVersion: 1, OK: true, Version: a.Version, Phase: "ddns", Results: []ddns.Result{}}
	}
	return ddns.Report{APIVersion: 1, OK: false, Version: a.Version, Phase: "ddns", Results: []ddns.Result{}, Error: err.Error()}
}

func (a App) newACME(cfg config.Snapshot) acme.Service {
	return acme.NewService(a.HomeDir, a.newLogger(cfg))
}

func (a App) CertificateStatus(ctx context.Context) acme.StatusReport {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return acme.StatusReport{APIVersion: 1, OK: false, Version: a.Version, Phase: acme.Phase, Certificates: []acme.CertificateStatus{}, Error: err.Error()}
	}
	return a.newACME(cfg).Status(a.Version, cfg)
}

func (a App) RenewCertificate(ctx context.Context, id string) (acme.IssueReport, error) {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		r := acme.IssueReport{APIVersion: 1, OK: false, Version: a.Version, Phase: acme.Phase, Certificate: id, Error: err.Error()}
		return r, err
	}
	cert, err := acme.FindCertificate(cfg, id)
	if err != nil {
		r := acme.IssueReport{APIVersion: 1, OK: false, Version: a.Version, Phase: acme.Phase, Certificate: id, Error: err.Error()}
		return r, err
	}
	renewCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	return a.newACME(cfg).Issue(renewCtx, a.Version, cfg, cert)
}

func (a App) RenewDueCertificates(ctx context.Context) acme.RenewReport {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return acme.RenewReport{APIVersion: 1, OK: false, Version: a.Version, Phase: acme.Phase, Results: []acme.IssueReport{}, Error: err.Error()}
	}
	return a.newACME(cfg).RenewDue(ctx, a.Version, cfg)
}

func (a App) runACMECycle(work daemonWork, generation *daemonGeneration, log *logger.Logger) acme.RenewReport {
	var report acme.RenewReport
	if a.ACMERenewDue != nil {
		report = a.ACMERenewDue(work.Context, a.Version, work.Config)
	} else {
		svc := acme.NewService(a.HomeDir, log)
		svc.Commit = func(fn func() error) (bool, error) {
			return generation.Commit(work.Generation, fn)
		}
		report = svc.RenewDue(work.Context, a.Version, work.Config)
	}
	if work.Context.Err() != nil || report.OK {
		return report
	}
	for _, result := range report.Results {
		if !result.OK && result.Error != "" {
			log.Errorf("certificate %s automatic renewal failed: %s", result.Certificate, result.Error)
		}
	}
	return report
}

func (a App) updateAccessRegionDaemon(ctx context.Context, key string) (access.UpdateReport, error) {
	if a.AccessUpdater != nil {
		return a.AccessUpdater(ctx, key)
	}
	return a.UpdateAccessRegion(ctx, key)
}

func (a App) ProxyStatus(ctx context.Context) proxy.Status {
	if st, err := proxy.ReadStatus(a.ProxyStatusPath, a.Version); err == nil {
		// proxy.json is daemon-owned runtime state. A hard crash can leave the
		// last successful snapshot behind, so listener booleans must never
		// outlive the daemon identity recorded in runtime.json. Keep configured
		// counts/domains as useful last-known metadata, but make listener truth
		// conservative when the common runtime is gone or cannot be verified.
		probe, probeErr := a.Runtime.Probe()
		if probeErr != nil {
			st.HTTPSListening = false
			st.HTTPListening = false
			st.HTTPSPort = 0
			st.HTTPPort = 0
			st.OK = false
			if st.Error != "" {
				st.Error += "; "
			}
			st.Error += "runtime probe: " + probeErr.Error()
			return st
		}
		if !probe.Running {
			st.HTTPSListening = false
			st.HTTPListening = false
			st.HTTPSPort = 0
			st.HTTPPort = 0
		}
		return st
	}
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return proxy.Status{APIVersion: 1, OK: false, Version: a.Version, Phase: proxy.Phase, Domains: []string{}, Error: err.Error()}
	}
	return proxy.BuildStatus(a.Version, cfg)
}

func (a App) AccessStatus(ctx context.Context) access.Status {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return access.Status{APIVersion: 1, OK: false, Phase: "access", Error: err.Error()}
	}
	return access.BuildStatus(cfg.Main, a.HomeDir)
}

func (a App) UpdateAccessRegion(ctx context.Context, key string) (access.UpdateReport, error) {
	updateCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return access.UpdateRegion(updateCtx, a.HomeDir, key)
}

func (a App) RefreshAccessRegion(ctx context.Context, key string) (access.UpdateReport, error) {
	updateCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return access.RefreshRegion(updateCtx, a.HomeDir, key)
}

func (a App) AccessRecent(ctx context.Context) access.RecentReport {
	// access.json is maintained by the long-lived proxy with geo and current_*
	// annotations already attached. Keep this CLI/API path strictly O(file size):
	// opening Access Management must never reparse region CIDR caches.
	return access.ReadRecent("")
}

func (a App) ClearDeniedAccessRecent() (access.RecentReport, error) {
	return access.ClearDeniedRecent("")
}

func (a App) ClearAccessRecent() (access.RecentReport, error) {
	return access.ClearRecent("")
}

func (a App) ClearAccessRecentEntry(ip, host string) (access.RecentReport, error) {
	return access.ClearRecentEntry("", ip, host)
}

// prepareAccessRegion makes daemon startup/reload resilient when an enabled
// region cache was removed or has gone stale. A validated stale dual-stack
// cache remains usable; no-cache failures still fail closed when proxy.Apply
// loads the policy.
func (a App) prepareAccessRegion(ctx context.Context, cfg config.Snapshot, log *logger.Logger, reason string) error {
	if !cfg.Main.AccessEnabled || strings.TrimSpace(cfg.Main.AccessRegion) == "" {
		return nil
	}
	report, err := a.UpdateAccessRegion(ctx, cfg.Main.AccessRegion)
	if err != nil {
		if log != nil {
			log.Warnf("access region %s preparation failed region=%s: %v", reason, cfg.Main.AccessRegion, err)
		}
		return err
	}
	if log != nil {
		if report.Warning != "" {
			log.Warnf("access region %s using validated stale cache region=%s ipv4=%d ipv6=%d: %s", reason, report.Region, report.IPv4, report.IPv6, report.Warning)
		} else if report.Source != "cache" {
			log.Infof("access region %s prepared region=%s ipv4=%d ipv6=%d source=%s", reason, report.Region, report.IPv4, report.IPv6, report.Source)
		}
	}
	return nil
}

func (a App) FirewallStatus() firewall.Status { return a.Firewall.Read(a.Version) }

func (a App) ApplyFirewall(ctx context.Context) (firewall.Status, error) {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return firewall.Status{APIVersion: 1, OK: false, Version: a.Version, Phase: firewall.Phase, Error: err.Error()}, err
	}
	return a.Firewall.Apply(ctx, a.Version, cfg)
}

func (a App) CleanupFirewall(ctx context.Context) firewall.Status {
	return a.Firewall.Cleanup(ctx, a.Version)
}

func (a App) WOLStatus(ctx context.Context) wol.Status {
	cfg, err := a.Config.Reload(ctx)
	return wol.BuildStatus(a.Version, cfg, err)
}

func (a App) WakeWOLHost(ctx context.Context, id string) (wol.Report, error) {
	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		r := wol.BuildReport(a.Version, config.WOLHost{ID: id}, "", wol.SendResult{Interfaces: []string{}}, err)
		return r, err
	}
	host, err := wol.FindHost(cfg, id)
	if err != nil {
		r := wol.BuildReport(a.Version, config.WOLHost{ID: id}, cfg.Main.WOLInterface, wol.SendResult{Interfaces: []string{}}, err)
		return r, err
	}
	return a.sendWOL(ctx, cfg, host, cfg.Main.WOLInterface)
}

// WakeWOLDirect preserves the r6 CLI contract used by the frozen LuCI
// controller: homegate wol <interface> <mac>.
func (a App) WakeWOLDirect(ctx context.Context, ifname, mac string) (wol.Report, error) {
	// Preserve r6 module isolation: the legacy direct CLI can wake a host even
	// when an unrelated UCI business section is temporarily invalid.
	cfg, cfgErr := a.Config.Reload(ctx)
	if cfgErr != nil {
		cfg = config.Snapshot{Main: config.Main{
			LogLevel:     config.DefaultLogLevel,
			LogMaxLines:  config.DefaultLogMaxLines,
			WOLInterface: config.DefaultWOLInterface,
		}}
	}
	if ifname == "" {
		ifname = cfg.Main.WOLInterface
	}
	return a.sendWOL(ctx, cfg, config.WOLHost{MAC: mac}, ifname)
}

func (a App) sendWOL(ctx context.Context, cfg config.Snapshot, host config.WOLHost, ifname string) (wol.Report, error) {
	lan, err := a.Network.ResolveLAN(ifname)
	if err != nil {
		r := wol.BuildReport(a.Version, host, ifname, wol.SendResult{Interfaces: []string{}}, err)
		return r, err
	}
	sender := a.WOLSender
	if sender == nil {
		sender = wol.Sender{}
	}
	result, sendErr := sender.Send(lan.Bridge, lan.Members, host.MAC)
	report := wol.BuildReport(a.Version, host, lan.Bridge, result, sendErr)
	log := a.newLogger(cfg)
	for _, warning := range result.Warnings {
		log.Warnf("WOL partial send warning mac=%s interface=%s: %s", report.MAC, lan.Bridge, warning)
	}
	if sendErr != nil {
		log.Errorf("WOL send failed mac=%s interface=%s: %v", report.MAC, lan.Bridge, sendErr)
		return report, sendErr
	}
	log.Infof("WOL sent mac=%s interface=%s raw=%d udp=%d", report.MAC, lan.Bridge, report.RawSent, report.UDPSent)
	return report, nil
}

func enqueueLatest(ch chan daemonWork, work daemonWork) {
	select {
	case ch <- work:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- work:
	default:
	}
}

type ddnsCycleDone struct {
	Generation uint64
	Report     ddns.Report
}

type acmeCycleDone struct {
	Generation uint64
	Report     acme.RenewReport
}

type accessCycleDone struct {
	Generation uint64
	Decision   accessRecoveryDecision
}

type workerFault struct {
	Module     string
	Generation uint64
	Error      string
}

type ddnsRecoveryDecision struct {
	Failed    bool
	Retryable bool
	ErrorKind string
	Error     string
}

type acmeRecoveryDecision struct {
	Failed    bool
	Retryable bool
	ErrorKind string
	Error     string
}

type accessRecoveryDecision struct {
	Failed    bool
	Retryable bool
	ErrorKind string
	Error     string
}

func classifyDDNSRecovery(report ddns.Report) ddnsRecoveryDecision {
	var firstPermanent *ddns.Result
	var firstRetryable *ddns.Result
	for i := range report.Results {
		result := &report.Results[i]
		if result.Status != "error" {
			continue
		}
		if result.ErrorKind == string(dnsprovider.ErrorContextCanceled) {
			continue
		}
		if result.Retryable {
			if firstRetryable == nil {
				firstRetryable = result
			}
		} else if firstPermanent == nil {
			firstPermanent = result
		}
	}
	pick := firstRetryable
	if pick == nil {
		pick = firstPermanent
	}
	if pick == nil {
		return ddnsRecoveryDecision{}
	}
	message := strings.TrimSpace(pick.Message)
	if message == "" {
		message = strings.TrimSpace(report.Error)
	}
	return ddnsRecoveryDecision{
		Failed:    true,
		Retryable: pick.Retryable,
		ErrorKind: strings.TrimSpace(pick.ErrorKind),
		Error:     message,
	}
}

func classifyACMERecovery(report acme.RenewReport) acmeRecoveryDecision {
	var firstPermanent *acme.IssueReport
	var firstRetryable *acme.IssueReport
	for i := range report.Results {
		result := &report.Results[i]
		if result.OK || result.Error == "" || result.ErrorKind == string(dnsprovider.ErrorContextCanceled) {
			continue
		}
		if result.Retryable {
			if firstRetryable == nil {
				firstRetryable = result
			}
		} else if firstPermanent == nil {
			firstPermanent = result
		}
	}
	// Permanent failures take precedence for ACME. Retrying an entire due-cert
	// batch while one certificate already needs user action would repeatedly hit
	// that permanent failure and can create avoidable ACME/provider traffic.
	pick := firstPermanent
	if pick == nil {
		pick = firstRetryable
	}
	if pick == nil {
		return acmeRecoveryDecision{}
	}
	kind := strings.TrimSpace(pick.ErrorKind)
	if kind == "" {
		kind = string(dnsprovider.ErrorUnknown)
	}
	return acmeRecoveryDecision{Failed: true, Retryable: pick.Retryable, ErrorKind: kind, Error: strings.TrimSpace(pick.Error)}
}

func classifyAccessRecovery(report access.UpdateReport, err error) accessRecoveryDecision {
	message := strings.TrimSpace(report.Warning)
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	if message == "" {
		return accessRecoveryDecision{}
	}
	if errors.Is(err, context.Canceled) {
		return accessRecoveryDecision{}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return accessRecoveryDecision{Failed: true, Retryable: true, ErrorKind: string(dnsprovider.ErrorTimeout), Error: message}
	}
	if strings.Contains(strings.ToLower(message), "unsupported access region") {
		return accessRecoveryDecision{Failed: true, Retryable: false, ErrorKind: string(dnsprovider.ErrorInvalidRequest), Error: message}
	}
	var netErr net.Error
	if err != nil && errors.As(err, &netErr) {
		return accessRecoveryDecision{Failed: true, Retryable: true, ErrorKind: string(dnsprovider.ErrorNetworkUnavailable), Error: message}
	}
	// A validated stale cache is deliberately kept active when the public region
	// source is temporarily unavailable. Surface that safe degradation and retry
	// without weakening the current policy.
	if report.Source == "stale-cache" || strings.Contains(message, "HTTP 429") || strings.Contains(message, "HTTP 5") || strings.Contains(message, "downloaded region list") {
		return accessRecoveryDecision{Failed: true, Retryable: true, ErrorKind: string(dnsprovider.ErrorTemporary), Error: message}
	}
	return accessRecoveryDecision{Failed: true, Retryable: false, ErrorKind: "runtime_failure", Error: message}
}

func enqueueLatestDDNSDone(ch chan ddnsCycleDone, result ddnsCycleDone) {
	select {
	case ch <- result:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- result:
	default:
	}
}

func enqueueLatestACMEDone(ch chan acmeCycleDone, result acmeCycleDone) {
	select {
	case ch <- result:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- result:
	default:
	}
}

func enqueueLatestAccessDone(ch chan accessCycleDone, result accessCycleDone) {
	select {
	case ch <- result:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- result:
	default:
	}
}

func reportWorkerPanic(ctx context.Context, ch chan workerFault, module string, generation uint64) {
	if recovered := recover(); recovered != nil {
		fault := workerFault{
			Module:     module,
			Generation: generation,
			Error:      fmt.Sprintf("%s worker panic isolated", strings.ToUpper(module)),
		}
		select {
		case ch <- fault:
		case <-ctx.Done():
		}
	}
}

type runtimeReloadResult struct {
	Snapshot           config.Snapshot
	Work               daemonWork
	Restored           bool
	FirewallReconciled bool
	FirewallRetry      bool
}

// reconcileRuntimeCandidate is the Phase 4G daemon reload acceptance boundary.
// Proxy first prepares routes/policy/listeners without publishing them. Firewall
// then attempts the same candidate while Config.Current and the active Proxy
// remain unchanged. Only after Firewall succeeds does Proxy commit, followed by
// Config.Current. If Firewall rejects the candidate, its previous rules are
// restored from the unchanged current snapshot and the prepared Proxy is
// aborted.
func (a App) reconcileRuntimeCandidate(ctx context.Context, proxyManager *proxy.Manager, generation *daemonGeneration, log *logger.Logger) (runtimeReloadResult, error) {
	next, err := a.Config.LoadCandidate(ctx)
	if err != nil {
		return runtimeReloadResult{}, err
	}
	current, ok := a.Config.Current()
	if !ok {
		return runtimeReloadResult{}, errors.New("no current configuration available for runtime reconcile")
	}
	_ = a.prepareAccessRegion(ctx, next, log, "reload")

	candidateWork := generation.Advance(next)
	prepared, err := proxyManager.PrepareGeneration(ctx, next, candidateWork.Generation)
	if err != nil {
		restoreWork := generation.Advance(current)
		proxyManager.AdoptGeneration(restoreWork.Generation)
		return runtimeReloadResult{Snapshot: current, Work: restoreWork, Restored: true}, err
	}

	_, fwErr := a.Firewall.Apply(ctx, a.Version, next)
	if fwErr != nil && firewall.RuntimeFailed(fwErr) {
		proxyManager.AbortPrepared(prepared)
		restoreWork := generation.Advance(current)
		proxyManager.AdoptGeneration(restoreWork.Generation)

		_, restoreErr := a.Firewall.Apply(ctx, a.Version, current)
		result := runtimeReloadResult{
			Snapshot:           current,
			Work:               restoreWork,
			Restored:           true,
			FirewallReconciled: true,
		}
		if restoreErr != nil && firewall.RuntimeFailed(restoreErr) {
			result.FirewallRetry = firewall.Retryable(restoreErr)
			return result, errors.Join(
				fmt.Errorf("candidate firewall apply: %w", fwErr),
				fmt.Errorf("restore previous firewall: %w", restoreErr),
			)
		}
		if restoreErr != nil && firewall.StatusWriteFailed(restoreErr) && log != nil {
			log.Errorf("restored firewall but status publication failed: %v", restoreErr)
		}
		return result, fmt.Errorf("candidate firewall apply: %w", fwErr)
	}
	if fwErr != nil && firewall.StatusWriteFailed(fwErr) && log != nil {
		log.Errorf("firewall candidate active but status publication failed: %v", fwErr)
	}

	proxyManager.CommitPrepared(ctx, prepared)
	a.Config.Commit(next)
	return runtimeReloadResult{Snapshot: next, Work: candidateWork, FirewallReconciled: true}, nil
}

func (a App) RunDaemon(ctx context.Context) error {
	daemonLock, err := runtimestate.AcquireDaemonLock(a.DaemonLockPath)
	if err != nil {
		return err
	}
	defer func() { _ = daemonLock.Close() }()

	cfg, err := a.Config.Reload(ctx)
	if err != nil {
		return err
	}
	log := a.newLogger(cfg)
	recoveryReport := recovery.Empty(a.Version)
	publishRecovery := func() {
		if err := a.Recovery.Write(recoveryReport); err != nil {
			log.Errorf("write recovery status: %v", err)
		}
	}
	clearRecoveryModule := func(module string) {
		if !recoveryReport.HasModule(module) {
			return
		}
		recoveryReport.ClearModule(module)
		publishRecovery()
	}
	publishRecovery()
	defer func() {
		if err := a.Recovery.Clear(); err != nil {
			log.Errorf("clear recovery status: %v", err)
		}
	}()
	state, err := a.Runtime.MarkStarted(a.Version)
	if err != nil {
		return err
	}
	defer func() {
		if err := a.Runtime.Clear(state.PID); err != nil {
			log.Errorf("clear runtime state: %v", err)
		}
	}()

	daemonCtx, cancelDaemon := context.WithCancel(ctx)
	defer cancelDaemon()
	generation := newDaemonGeneration(daemonCtx)

	log.Infof("HomeGate %s common runtime started pid=%d enabled=%t", a.Version, state.PID, cfg.Main.Enabled)

	proxyManager := proxy.New(a.HomeDir, log, a.Version)
	if a.ProxyStatusPath != "" {
		proxyManager.StatusPath = a.ProxyStatusPath
	}

	// LuCI validates region data before committing, but daemon startup must also
	// recover safely if a cache was removed outside LuCI or after a restore.
	_ = a.prepareAccessRegion(ctx, cfg, log, "startup")

	// Firewall reconciliation is serialized in the daemon select loop. On cold
	// boot QWRT may start HomeGate before PPPoE has acquired its public IPv6; in
	// that case arm a bounded retry sequence instead of relying on a hotplug
	// event that may have already raced past daemon signal registration.
	var firewallRetryTimer *time.Timer
	var firewallRetryC <-chan time.Time
	firewallRetryAttempt := 0
	firewallCfg := cfg
	stopFirewallRetry := func(reset bool) {
		if firewallRetryTimer != nil {
			if !firewallRetryTimer.Stop() {
				select {
				case <-firewallRetryTimer.C:
				default:
				}
			}
		}
		firewallRetryC = nil
		if reset {
			firewallRetryAttempt = 0
		}
	}
	scheduleFirewallRetry := func(lastErr error) {
		errorText := "WAN/public IPv6 unavailable"
		if lastErr != nil {
			errorText = lastErr.Error()
		}
		if firewallRetryAttempt >= len(firewallRetryDelays) {
			log.Errorf("firewall recovery exhausted after %d bounded retries", firewallRetryAttempt)
			firewallRetryC = nil
			recoveryReport.Set("firewall", recovery.StateDegraded, true, firewallRetryAttempt, len(firewallRetryDelays), time.Time{}, string(dnsprovider.ErrorNetworkUnavailable), errorText, time.Now())
			publishRecovery()
			return
		}
		delay := firewallRetryDelays[firewallRetryAttempt]
		firewallRetryAttempt++
		if firewallRetryTimer == nil {
			firewallRetryTimer = time.NewTimer(delay)
		} else {
			firewallRetryTimer.Reset(delay)
		}
		firewallRetryC = firewallRetryTimer.C
		nextRetry := time.Now().Add(delay)
		recoveryReport.Set("firewall", recovery.StateRetrying, true, firewallRetryAttempt, len(firewallRetryDelays), nextRetry, string(dnsprovider.ErrorNetworkUnavailable), errorText, time.Now())
		publishRecovery()
		log.Infof("firewall recovery scheduled attempt=%d/%d delay=%s", firewallRetryAttempt, len(firewallRetryDelays), delay)
	}
	defer stopFirewallRetry(false)

	var proxyRetryTimer *time.Timer
	var proxyRetryC <-chan time.Time
	proxyRetryAttempt := 0
	stopProxyRetry := func(reset bool) {
		if proxyRetryTimer != nil {
			if !proxyRetryTimer.Stop() {
				select {
				case <-proxyRetryTimer.C:
				default:
				}
			}
		}
		proxyRetryC = nil
		if reset {
			proxyRetryAttempt = 0
		}
	}
	scheduleProxyRetry := func(lastErr error) {
		errorText := "Proxy listener unavailable"
		if lastErr != nil {
			errorText = lastErr.Error()
		}
		// HTTP and HTTPS can terminate as part of the same runtime fault. One
		// desired-state reconcile repairs both, so never stack multiple Proxy
		// timers or burn the bounded retry budget for the same outage.
		if proxyRetryC != nil {
			return
		}
		if proxyRetryAttempt >= len(proxyRecoveryDelays) {
			proxyRetryC = nil
			recoveryReport.Set("proxy", recovery.StateDegraded, true, proxyRetryAttempt, len(proxyRecoveryDelays), time.Time{}, "runtime_failure", errorText, time.Now())
			publishRecovery()
			log.Warnf("Proxy recovery exhausted after %d bounded retries; waiting for config or WAN event", proxyRetryAttempt)
			return
		}
		delay := proxyRecoveryDelays[proxyRetryAttempt]
		proxyRetryAttempt++
		if proxyRetryTimer == nil {
			proxyRetryTimer = time.NewTimer(delay)
		} else {
			proxyRetryTimer.Reset(delay)
		}
		proxyRetryC = proxyRetryTimer.C
		nextRetry := time.Now().Add(delay)
		recoveryReport.Set("proxy", recovery.StateRetrying, true, proxyRetryAttempt, len(proxyRecoveryDelays), nextRetry, "runtime_failure", errorText, time.Now())
		publishRecovery()
		log.Infof("Proxy recovery scheduled attempt=%d/%d delay=%s", proxyRetryAttempt, len(proxyRecoveryDelays), delay)
	}
	defer stopProxyRetry(false)

	var ddnsRetryTimer *time.Timer
	var ddnsRetryC <-chan time.Time
	ddnsRetryAttempt := 0
	stopDDNSRetry := func(reset bool) {
		if ddnsRetryTimer != nil {
			if !ddnsRetryTimer.Stop() {
				select {
				case <-ddnsRetryTimer.C:
				default:
				}
			}
		}
		ddnsRetryC = nil
		if reset {
			ddnsRetryAttempt = 0
		}
	}
	scheduleDDNSRetry := func(decision ddnsRecoveryDecision) {
		errorKind := strings.TrimSpace(decision.ErrorKind)
		if errorKind == "" {
			errorKind = string(dnsprovider.ErrorTemporary)
		}
		errorText := strings.TrimSpace(decision.Error)
		if errorText == "" {
			errorText = "DDNS temporary failure"
		}
		if ddnsRetryAttempt >= len(ddnsRecoveryDelays) {
			ddnsRetryC = nil
			recoveryReport.Set("ddns", recovery.StateDegraded, true, ddnsRetryAttempt, len(ddnsRecoveryDelays), time.Time{}, errorKind, errorText, time.Now())
			publishRecovery()
			log.Warnf("DDNS recovery exhausted after %d bounded retries; waiting for timer or network/config event", ddnsRetryAttempt)
			return
		}
		delay := ddnsRecoveryDelays[ddnsRetryAttempt]
		ddnsRetryAttempt++
		if ddnsRetryTimer == nil {
			ddnsRetryTimer = time.NewTimer(delay)
		} else {
			ddnsRetryTimer.Reset(delay)
		}
		ddnsRetryC = ddnsRetryTimer.C
		nextRetry := time.Now().Add(delay)
		recoveryReport.Set("ddns", recovery.StateRetrying, true, ddnsRetryAttempt, len(ddnsRecoveryDelays), nextRetry, errorKind, errorText, time.Now())
		publishRecovery()
		log.Infof("DDNS recovery scheduled attempt=%d/%d delay=%s kind=%s", ddnsRetryAttempt, len(ddnsRecoveryDelays), delay, errorKind)
	}
	defer stopDDNSRetry(false)

	var acmeRetryTimer *time.Timer
	var acmeRetryC <-chan time.Time
	acmeRetryAttempt := 0
	stopACMERetry := func(reset bool) {
		if acmeRetryTimer != nil {
			if !acmeRetryTimer.Stop() {
				select {
				case <-acmeRetryTimer.C:
				default:
				}
			}
		}
		acmeRetryC = nil
		if reset {
			acmeRetryAttempt = 0
		}
	}
	scheduleACMERetry := func(decision acmeRecoveryDecision) {
		errorKind := strings.TrimSpace(decision.ErrorKind)
		if errorKind == "" {
			errorKind = string(dnsprovider.ErrorTemporary)
		}
		errorText := strings.TrimSpace(decision.Error)
		if errorText == "" {
			errorText = "ACME temporary failure"
		}
		if acmeRetryAttempt >= len(acmeRecoveryDelays) {
			acmeRetryC = nil
			recoveryReport.Set("acme", recovery.StateDegraded, true, acmeRetryAttempt, len(acmeRecoveryDelays), time.Time{}, errorKind, errorText, time.Now())
			publishRecovery()
			log.Warnf("ACME recovery exhausted after %d bounded retries; waiting for timer or network/config event", acmeRetryAttempt)
			return
		}
		delay := acmeRecoveryDelays[acmeRetryAttempt]
		acmeRetryAttempt++
		if acmeRetryTimer == nil {
			acmeRetryTimer = time.NewTimer(delay)
		} else {
			acmeRetryTimer.Reset(delay)
		}
		acmeRetryC = acmeRetryTimer.C
		nextRetry := time.Now().Add(delay)
		recoveryReport.Set("acme", recovery.StateRetrying, true, acmeRetryAttempt, len(acmeRecoveryDelays), nextRetry, errorKind, errorText, time.Now())
		publishRecovery()
		log.Infof("ACME recovery scheduled attempt=%d/%d delay=%s kind=%s", acmeRetryAttempt, len(acmeRecoveryDelays), delay, errorKind)
	}
	defer stopACMERetry(false)

	var accessRetryTimer *time.Timer
	var accessRetryC <-chan time.Time
	accessRetryAttempt := 0
	stopAccessRetry := func(reset bool) {
		if accessRetryTimer != nil {
			if !accessRetryTimer.Stop() {
				select {
				case <-accessRetryTimer.C:
				default:
				}
			}
		}
		accessRetryC = nil
		if reset {
			accessRetryAttempt = 0
		}
	}
	scheduleAccessRetry := func(decision accessRecoveryDecision) {
		errorKind := strings.TrimSpace(decision.ErrorKind)
		if errorKind == "" {
			errorKind = string(dnsprovider.ErrorTemporary)
		}
		errorText := strings.TrimSpace(decision.Error)
		if errorText == "" {
			errorText = "Access temporary failure"
		}
		if accessRetryAttempt >= len(accessRecoveryDelays) {
			accessRetryC = nil
			recoveryReport.Set("access", recovery.StateDegraded, true, accessRetryAttempt, len(accessRecoveryDelays), time.Time{}, errorKind, errorText, time.Now())
			publishRecovery()
			log.Warnf("Access recovery exhausted after %d bounded retries; waiting for timer or network/config event", accessRetryAttempt)
			return
		}
		delay := accessRecoveryDelays[accessRetryAttempt]
		accessRetryAttempt++
		if accessRetryTimer == nil {
			accessRetryTimer = time.NewTimer(delay)
		} else {
			accessRetryTimer.Reset(delay)
		}
		accessRetryC = accessRetryTimer.C
		nextRetry := time.Now().Add(delay)
		recoveryReport.Set("access", recovery.StateRetrying, true, accessRetryAttempt, len(accessRecoveryDelays), nextRetry, errorKind, errorText, time.Now())
		publishRecovery()
		log.Infof("Access recovery scheduled attempt=%d/%d delay=%s kind=%s", accessRetryAttempt, len(accessRecoveryDelays), delay, errorKind)
	}
	defer stopAccessRetry(false)

	initialWork := generation.Work(cfg)
	if _, proxyErr := proxyManager.ApplyGeneration(ctx, cfg, initialWork.Generation); proxyErr != nil {
		if cleanup := a.Firewall.Cleanup(ctx, a.Version); !cleanup.OK {
			log.Errorf("firewall cleanup after proxy startup failure: %s", cleanup.Error)
		}
		log.Errorf("proxy startup apply failed: %v", proxyErr)
		return fmt.Errorf("proxy startup apply: %w", proxyErr)
	}
	fw, fwErr := a.Firewall.Apply(ctx, a.Version, cfg)
	if fwErr != nil && firewall.RuntimeFailed(fwErr) {
		log.Errorf("firewall apply failed: %v", fwErr)
		if firewall.Retryable(fwErr) {
			scheduleFirewallRetry(fwErr)
		} else {
			startupErr := fmt.Errorf("firewall startup apply: %w", fwErr)
			if closeErr := proxyManager.Close(ctx); closeErr != nil {
				log.Errorf("proxy cleanup after firewall startup failure: %v", closeErr)
				return errors.Join(startupErr, fmt.Errorf("close proxy after firewall startup failure: %w", closeErr))
			}
			return startupErr
		}
	} else {
		if fwErr != nil && firewall.StatusWriteFailed(fwErr) {
			log.Errorf("firewall active but status publication failed: %v", fwErr)
		}
		if fw.Active {
			log.Infof("firewall active wan6=%s source=%s https=%s http=%s", fw.WANDevice, fw.WANSource, fw.HTTPS, fw.HTTP)
		}
	}
	defer func() {
		if cleanup := a.Firewall.Cleanup(context.Background(), a.Version); !cleanup.OK {
			log.Errorf("firewall shutdown cleanup failed: %s", cleanup.Error)
		}
		_ = proxyManager.Close(context.Background())
	}()

	ddnsTrigger := make(chan daemonWork, 1)
	ddnsDone := make(chan ddnsCycleDone, 1)
	acmeTrigger := make(chan daemonWork, 1)
	acmeDone := make(chan acmeCycleDone, 1)
	accessTrigger := make(chan daemonWork, 1)
	accessDone := make(chan accessCycleDone, 1)
	workerFaults := make(chan workerFault, 3)

	events := scheduler.New(12)
	submitEvent := func(kind scheduler.Kind) {
		if !events.Submit(kind) {
			log.Errorf("scheduler queue full; event dropped kind=%s", kind)
		}
	}

	var workerWG sync.WaitGroup
	workerWG.Add(3)
	go func() {
		defer workerWG.Done()
		for {
			select {
			case <-daemonCtx.Done():
				return
			case work := <-ddnsTrigger:
				func() {
					defer reportWorkerPanic(daemonCtx, workerFaults, "ddns", work.Generation)
					report := a.runDDNSCycle(work.Context, work.Config, log)
					committed, err := generation.Commit(work.Generation, func() error {
						return a.DDNSStatus.Write(report)
					})
					if !committed {
						log.Debugf("discard stale DDNS generation=%d", work.Generation)
						return
					}
					if err != nil {
						log.Errorf("write DDNS status: %v", err)
					}
					enqueueLatestDDNSDone(ddnsDone, ddnsCycleDone{Generation: work.Generation, Report: report})
				}()
			}
		}
	}()
	go func() {
		defer workerWG.Done()
		for {
			select {
			case <-daemonCtx.Done():
				return
			case work := <-acmeTrigger:
				func() {
					defer reportWorkerPanic(daemonCtx, workerFaults, "acme", work.Generation)
					report := a.runACMECycle(work, generation, log)
					enqueueLatestACMEDone(acmeDone, acmeCycleDone{Generation: work.Generation, Report: report})
				}()
			}
		}
	}()
	go func() {
		defer workerWG.Done()
		for {
			select {
			case <-daemonCtx.Done():
				return
			case work := <-accessTrigger:
				func() {
					defer reportWorkerPanic(daemonCtx, workerFaults, "access", work.Generation)
					next := work.Config
					// Location labels are operational UI metadata, not an access-control
					// dependency. Keep a country-wide CN cache warm in the background when
					// public Web routes exist; failures never block or weaken the policy.
					var cnReport access.UpdateReport
					var cnErr error
					if enabledWebCount(next.Web) > 0 {
						cnReport, cnErr = a.updateAccessRegionDaemon(work.Context, "CN")
						if cnErr != nil {
							log.Debugf("access geo country refresh unavailable: %v", cnErr)
						} else if cnReport.Source != "cache" {
							log.Infof("access geo country refreshed ipv4=%d ipv6=%d source=%s", cnReport.IPv4, cnReport.IPv6, cnReport.Source)
						}
					}

					if !next.Main.AccessEnabled || strings.TrimSpace(next.Main.AccessRegion) == "" {
						enqueueLatestAccessDone(accessDone, accessCycleDone{Generation: work.Generation})
						return
					}
					var report access.UpdateReport
					var err error
					if strings.EqualFold(strings.TrimSpace(next.Main.AccessRegion), "CN") && cnErr == nil && cnReport.OK {
						report = cnReport
					} else {
						report, err = a.updateAccessRegionDaemon(work.Context, next.Main.AccessRegion)
					}
					if err != nil {
						if work.Context.Err() == nil {
							log.Warnf("access region refresh failed region=%s: %v", next.Main.AccessRegion, err)
						}
						decision := classifyAccessRecovery(report, err)
						enqueueLatestAccessDone(accessDone, accessCycleDone{Generation: work.Generation, Decision: decision})
						return
					}
					committed, err := proxyManager.RefreshAccessPolicyGeneration(next.Main, work.Generation)
					if err != nil {
						log.Warnf("access policy refresh failed region=%s: %v", next.Main.AccessRegion, err)
						enqueueLatestAccessDone(accessDone, accessCycleDone{Generation: work.Generation, Decision: accessRecoveryDecision{Failed: true, Retryable: false, ErrorKind: "runtime_failure", Error: err.Error()}})
						return
					}
					if !committed {
						log.Debugf("discard stale access policy generation=%d region=%s", work.Generation, next.Main.AccessRegion)
						return
					}
					if report.Warning != "" {
						log.Warnf("access region using validated stale cache region=%s ipv4=%d ipv6=%d: %s", report.Region, report.IPv4, report.IPv6, report.Warning)
					} else if report.Source != "cache" {
						log.Infof("access region refreshed region=%s ipv4=%d ipv6=%d source=%s", report.Region, report.IPv4, report.IPv6, report.Source)
					}
					decision := classifyAccessRecovery(report, nil)
					enqueueLatestAccessDone(accessDone, accessCycleDone{Generation: work.Generation, Decision: decision})
				}()
			}
		}
	}()

	// This defer is intentionally registered after the proxy/firewall cleanup
	// defer above, so it runs first: cancel configuration-dependent work, wait a
	// bounded interval for ACME DNS cleanup and other workers, then close network
	// listeners and firewall state.
	defer func() {
		generation.Stop()
		cancelDaemon()
		done := make(chan struct{})
		go func() {
			workerWG.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(25 * time.Second):
			log.Errorf("background worker shutdown timeout")
		}
	}()

	interval := time.Duration(cfg.Main.DDNSInterval) * time.Second
	ddnsTicker := time.NewTicker(interval)
	defer ddnsTicker.Stop()
	acmeTicker := time.NewTicker(12 * time.Hour)
	defer acmeTicker.Stop()
	accessTicker := time.NewTicker(24 * time.Hour)
	defer accessTicker.Stop()

	term := make(chan os.Signal, 2)
	reload := make(chan os.Signal, 2)
	wanChanged := make(chan os.Signal, 2)
	signal.Notify(term, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(reload, syscall.SIGHUP)
	signal.Notify(wanChanged, syscall.SIGUSR1)
	defer signal.Stop(term)
	defer signal.Stop(reload)
	defer signal.Stop(wanChanged)

	// Interface hotplug commonly arrives as a short burst (link, ifup and
	// address notifications for the same transition).  Queue-level dedup alone
	// cannot collapse signals that arrive just after the previous WAN event has
	// already been consumed.  Debounce at the event ingress so one physical WAN
	// transition produces one reconcile after the signal burst becomes quiet.
	// This is event coalescing, not a Stage 9 retry/backoff policy.
	const wanEventQuietPeriod = 250 * time.Millisecond
	var wanEventTimer *time.Timer
	var wanEventTimerC <-chan time.Time
	defer func() {
		if wanEventTimer != nil {
			wanEventTimer.Stop()
		}
	}()
	armWANEvent := func() {
		if wanEventTimer == nil {
			wanEventTimer = time.NewTimer(wanEventQuietPeriod)
			wanEventTimerC = wanEventTimer.C
			return
		}
		if !wanEventTimer.Stop() {
			select {
			case <-wanEventTimer.C:
			default:
			}
		}
		wanEventTimer.Reset(wanEventQuietPeriod)
		wanEventTimerC = wanEventTimer.C
	}

	// Startup module work enters the same bounded scheduler as later timer,
	// config and WAN events. Critical Proxy/Firewall startup acceptance above
	// remains synchronous so permanent startup failures keep fail-fast semantics.
	submitEvent(scheduler.EventStartup)

	for {
		select {
		case <-ctx.Done():
			log.Infof("HomeGate common runtime stopped")
			return nil
		case <-term:
			log.Infof("HomeGate common runtime stopped")
			return nil
		case <-ddnsTicker.C:
			submitEvent(scheduler.EventDDNSTimer)
		case <-acmeTicker.C:
			submitEvent(scheduler.EventACMETimer)
		case <-accessTicker.C:
			submitEvent(scheduler.EventAccessTimer)
		case <-firewallRetryC:
			firewallRetryC = nil
			submitEvent(scheduler.EventFirewallRetry)
		case <-proxyRetryC:
			proxyRetryC = nil
			submitEvent(scheduler.EventProxyRetry)
		case <-ddnsRetryC:
			ddnsRetryC = nil
			submitEvent(scheduler.EventDDNSRetry)
		case <-acmeRetryC:
			acmeRetryC = nil
			submitEvent(scheduler.EventACMERetry)
		case <-accessRetryC:
			accessRetryC = nil
			submitEvent(scheduler.EventAccessRetry)
		case done := <-ddnsDone:
			if !generation.IsCurrent(done.Generation) {
				continue
			}
			decision := classifyDDNSRecovery(done.Report)
			if !decision.Failed {
				stopDDNSRetry(true)
				clearRecoveryModule("ddns")
				continue
			}
			if decision.Retryable {
				scheduleDDNSRetry(decision)
				continue
			}
			stopDDNSRetry(true)
			errorKind := strings.TrimSpace(decision.ErrorKind)
			if errorKind == "" {
				errorKind = string(dnsprovider.ErrorInvalidRequest)
			}
			recoveryReport.Set("ddns", recovery.StateRequiresUserAction, false, 0, len(ddnsRecoveryDelays), time.Time{}, errorKind, decision.Error, time.Now())
			publishRecovery()
		case done := <-acmeDone:
			if !generation.IsCurrent(done.Generation) {
				continue
			}
			decision := classifyACMERecovery(done.Report)
			if !decision.Failed {
				stopACMERetry(true)
				clearRecoveryModule("acme")
				continue
			}
			if decision.Retryable {
				scheduleACMERetry(decision)
				continue
			}
			stopACMERetry(true)
			errorKind := strings.TrimSpace(decision.ErrorKind)
			if errorKind == "" {
				errorKind = string(dnsprovider.ErrorInvalidRequest)
			}
			recoveryReport.Set("acme", recovery.StateRequiresUserAction, false, 0, len(acmeRecoveryDelays), time.Time{}, errorKind, decision.Error, time.Now())
			publishRecovery()
		case done := <-accessDone:
			if !generation.IsCurrent(done.Generation) {
				continue
			}
			decision := done.Decision
			if !decision.Failed {
				stopAccessRetry(true)
				clearRecoveryModule("access")
				continue
			}
			if decision.Retryable {
				scheduleAccessRetry(decision)
				continue
			}
			stopAccessRetry(true)
			errorKind := strings.TrimSpace(decision.ErrorKind)
			if errorKind == "" {
				errorKind = string(dnsprovider.ErrorInvalidRequest)
			}
			recoveryReport.Set("access", recovery.StateRequiresUserAction, false, 0, len(accessRecoveryDelays), time.Time{}, errorKind, decision.Error, time.Now())
			publishRecovery()
		case failure := <-proxyManager.Failures():
			scheduleProxyRetry(failure.Err)
		case fault := <-workerFaults:
			if !generation.IsCurrent(fault.Generation) {
				continue
			}
			log.Errorf("background worker panic isolated module=%s; bounded recovery scheduled", fault.Module)
			switch fault.Module {
			case "ddns":
				scheduleDDNSRetry(ddnsRecoveryDecision{Failed: true, Retryable: true, ErrorKind: "runtime_failure", Error: fault.Error})
			case "acme":
				scheduleACMERetry(acmeRecoveryDecision{Failed: true, Retryable: true, ErrorKind: "runtime_failure", Error: fault.Error})
			case "access":
				scheduleAccessRetry(accessRecoveryDecision{Failed: true, Retryable: true, ErrorKind: "runtime_failure", Error: fault.Error})
			}
		case <-reload:
			submitEvent(scheduler.EventConfigChanged)
		case <-wanChanged:
			armWANEvent()
		case <-wanEventTimerC:
			wanEventTimerC = nil
			submitEvent(scheduler.EventWANChanged)
		case <-events.C():
			for {
				ev, ok := events.Next()
				if !ok {
					break
				}
				switch ev.Kind {
				case scheduler.EventStartup:
					if current, ok := a.Config.Current(); ok {
						work := generation.Work(current)
						enqueueLatest(ddnsTrigger, work)
						enqueueLatest(acmeTrigger, work)
						enqueueLatest(accessTrigger, work)
					}

				case scheduler.EventDDNSTimer:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(ddnsTrigger, generation.Work(current))
					}

				case scheduler.EventDDNSRetry:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(ddnsTrigger, generation.Work(current))
					}

				case scheduler.EventACMETimer:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(acmeTrigger, generation.Work(current))
					}

				case scheduler.EventACMERetry:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(acmeTrigger, generation.Work(current))
					}

				case scheduler.EventAccessTimer:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(accessTrigger, generation.Work(current))
					}

				case scheduler.EventAccessRetry:
					if current, ok := a.Config.Current(); ok {
						enqueueLatest(accessTrigger, generation.Work(current))
					}

				case scheduler.EventFirewallRetry:
					fw, fwErr := a.Firewall.Apply(ctx, a.Version, firewallCfg)
					if fwErr != nil && firewall.RuntimeFailed(fwErr) {
						log.Errorf("firewall recovery attempt=%d failed: %v", firewallRetryAttempt, fwErr)
						if firewall.Retryable(fwErr) {
							scheduleFirewallRetry(fwErr)
						} else {
							recoveryReport.Set("firewall", recovery.StateRequiresUserAction, false, firewallRetryAttempt, len(firewallRetryDelays), time.Time{}, "runtime_failure", fwErr.Error(), time.Now())
							publishRecovery()
						}
						continue
					}
					stopFirewallRetry(true)
					clearRecoveryModule("firewall")
					if fwErr != nil && firewall.StatusWriteFailed(fwErr) {
						log.Errorf("firewall recovered but status publication failed: %v", fwErr)
					}
					if fw.Active {
						log.Infof("firewall recovered wan6=%s source=%s https=%s http=%s", fw.WANDevice, fw.WANSource, fw.HTTPS, fw.HTTP)
					}

				case scheduler.EventProxyRetry:
					current, ok := a.Config.Current()
					if !ok {
						scheduleProxyRetry(errors.New("no current configuration"))
						continue
					}
					work := generation.Work(current)
					st, proxyErr := proxyManager.ApplyGeneration(ctx, current, work.Generation)
					if proxyErr != nil {
						log.Errorf("Proxy recovery attempt=%d failed: %v", proxyRetryAttempt, proxyErr)
						scheduleProxyRetry(proxyErr)
						continue
					}
					stopProxyRetry(true)
					clearRecoveryModule("proxy")
					log.Infof("Proxy recovered https_listening=%t http_listening=%t https_port=%d http_port=%d", st.HTTPSListening, st.HTTPListening, st.HTTPSPort, st.HTTPPort)

				case scheduler.EventWANChanged:
					current, ok := a.Config.Current()
					if !ok {
						log.Errorf("WAN reconcile skipped: no current configuration")
						continue
					}
					// The pre-Stage8 hotplug path sent SIGHUP, which cancelled in-flight
					// configuration-dependent work and reran all module cycles. Preserve
					// that cancellation behavior without pretending the UCI config changed.
					stopDDNSRetry(true)
					stopACMERetry(true)
					stopAccessRetry(true)
					work := generation.Advance(current)
					proxyManager.AdoptGeneration(work.Generation)
					firewallCfg = current
					stopFirewallRetry(true)
					fw, fwErr := a.Firewall.Apply(ctx, a.Version, current)
					if fwErr != nil && firewall.RuntimeFailed(fwErr) {
						log.Errorf("WAN firewall reconcile failed: %v", fwErr)
						if firewall.Retryable(fwErr) {
							scheduleFirewallRetry(fwErr)
						} else {
							recoveryReport.Set("firewall", recovery.StateRequiresUserAction, false, 0, len(firewallRetryDelays), time.Time{}, "runtime_failure", fwErr.Error(), time.Now())
							publishRecovery()
						}
					} else {
						clearRecoveryModule("firewall")
						if fwErr != nil && firewall.StatusWriteFailed(fwErr) {
							log.Errorf("WAN firewall active but status publication failed: %v", fwErr)
						}
						if fw.Active {
							log.Infof("WAN reconciled firewall wan6=%s source=%s https=%s http=%s", fw.WANDevice, fw.WANSource, fw.HTTPS, fw.HTTP)
						}
					}
					enqueueLatest(ddnsTrigger, work)
					enqueueLatest(acmeTrigger, work)
					enqueueLatest(accessTrigger, work)
					if recoveryReport.HasModule("proxy") {
						stopProxyRetry(true)
						submitEvent(scheduler.EventProxyRetry)
					}
					log.Debugf("WAN event generation=%d", work.Generation)

				case scheduler.EventConfigChanged:
					reloadResult, reloadErr := a.reconcileRuntimeCandidate(ctx, proxyManager, generation, log)
					if reloadErr != nil {
						if reloadResult.Restored {
							stopDDNSRetry(true)
							stopACMERetry(true)
							stopAccessRetry(true)
							enqueueLatest(ddnsTrigger, reloadResult.Work)
							enqueueLatest(acmeTrigger, reloadResult.Work)
							enqueueLatest(accessTrigger, reloadResult.Work)
						}
						if reloadResult.FirewallReconciled {
							stopFirewallRetry(true)
							if reloadResult.FirewallRetry {
								scheduleFirewallRetry(reloadErr)
							} else {
								clearRecoveryModule("firewall")
							}
						}
						log.Errorf("configuration reload rejected: %v", reloadErr)
						continue
					}

					next := reloadResult.Snapshot
					candidateWork := reloadResult.Work
					stopProxyRetry(true)
					clearRecoveryModule("proxy")
					stopDDNSRetry(true)
					stopACMERetry(true)
					stopAccessRetry(true)
					log.Reconfigure(next.Main.LogLevel, next.Main.LogMaxLines)
					firewallCfg = next
					stopFirewallRetry(true)
					clearRecoveryModule("firewall")
					if fw := a.Firewall.Read(a.Version); fw.Active {
						log.Infof("firewall active wan6=%s source=%s https=%s http=%s", fw.WANDevice, fw.WANSource, fw.HTTPS, fw.HTTP)
					}
					ddnsTicker.Reset(time.Duration(next.Main.DDNSInterval) * time.Second)
					enqueueLatest(ddnsTrigger, candidateWork)
					enqueueLatest(acmeTrigger, candidateWork)
					enqueueLatest(accessTrigger, candidateWork)
					log.Debugf("runtime generation committed=%d", candidateWork.Generation)
					log.Infof("configuration reloaded enabled=%t log_level=%s log_max_lines=%d ddns_interval=%d renew_days=%d web_enabled=%d", next.Main.Enabled, next.Main.LogLevel, next.Main.LogMaxLines, next.Main.DDNSInterval, next.Main.RenewDays, enabledWebCount(next.Web))
				}
			}
		}
	}

}

func enabledWebCount(rules []config.WebRule) int {
	n := 0
	for _, r := range rules {
		if r.Enabled {
			n++
		}
	}
	return n
}

func (a App) Check(ctx context.Context) (status.Report, error) {
	r := a.Status(ctx)
	if !r.OK {
		if r.Error != "" {
			return r, fmt.Errorf("homegate unhealthy: %s", r.Error)
		}
		return r, fmt.Errorf("homegate unhealthy")
	}
	return r, nil
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	return 1
}

func Fatalf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
