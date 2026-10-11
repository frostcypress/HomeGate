package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"homegate.local/homegate/internal/access"
	"homegate.local/homegate/internal/certstore"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/logger"
	"homegate.local/homegate/internal/runtimefile"
)

const (
	Phase             = "proxy"
	DefaultStatusPath = "/var/run/homegate/proxy.json"
	denyLogInterval   = time.Minute
	denyLogMaxEntries = 1024
)

type route struct {
	Domain string
	Target *url.URL
	Proxy  *httputil.ReverseProxy
	HTTPS  bool
	CertID string
}

type Status struct {
	APIVersion     int      `json:"api_version"`
	OK             bool     `json:"ok"`
	Version        string   `json:"version"`
	Phase          string   `json:"phase"`
	Configured     int      `json:"configured"`
	Enabled        int      `json:"enabled"`
	HTTPSListening bool     `json:"https_listening"`
	HTTPListening  bool     `json:"http_listening"`
	HTTPSPort      int      `json:"https_port,omitempty"`
	HTTPPort       int      `json:"http_port,omitempty"`
	Domains        []string `json:"domains"`
	AccessEnabled  bool     `json:"access_enabled"`
	AccessRegion   string   `json:"access_region,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// ListenerFailure reports an unexpected failure of an active Proxy listener.
// Planned shutdown/reload paths return http.ErrServerClosed and are never
// published here. The daemon consumes this channel to run bounded self-heal
// without conflating listener failure with configuration changes.
type ListenerFailure struct {
	Protocol string
	Port     int
	Err      error
}

type certificateCacheEntry struct {
	pair     *tls.Certificate
	certInfo os.FileInfo
	keyInfo  os.FileInfo
}

type denyLogEntry struct {
	last time.Time
	seq  uint64
}

type denyLogSlot struct {
	key string
	seq uint64
}

type Manager struct {
	mu                   sync.RWMutex
	homeDir              string
	log                  *logger.Logger
	routes               map[string]route
	httpsServer          *http.Server
	httpServer           *http.Server
	httpsListener        net.Listener
	httpListener         net.Listener
	httpsPort            int
	httpPort             int
	publicHTTPSPort      int
	accessPolicy         *access.Policy
	accessRecorder       *access.Recorder
	accessGeo            *access.GeoResolver
	accessGeoFingerprint string
	accessGeoLoading     string
	denyLogged           map[string]denyLogEntry
	denyRing             []denyLogSlot
	denyNext             int
	denySeq              uint64
	certMu               sync.RWMutex
	certCache            map[string]certificateCacheEntry
	version              string
	StatusPath           string
	last                 Status
	activeCfg            config.Snapshot
	hasActiveCfg         bool
	runtimeGeneration    uint64
	failures             chan ListenerFailure
}

type listenerCandidate struct {
	need  bool
	reuse bool
	port  int
	ln    net.Listener
	srv   *http.Server
}

type PreparedRuntime struct {
	cfg            config.Snapshot
	generation     uint64
	routes         map[string]route
	policy         *access.Policy
	recorder       *access.Recorder
	httpsCandidate listenerCandidate
	httpCandidate  listenerCandidate
}

func New(homeDir string, log *logger.Logger, version string) *Manager {
	return &Manager{homeDir: homeDir, log: log, version: version, StatusPath: DefaultStatusPath, routes: map[string]route{}, accessRecorder: access.NewRecorder(""), denyLogged: map[string]denyLogEntry{}, denyRing: make([]denyLogSlot, denyLogMaxEntries), certCache: map[string]certificateCacheEntry{}, failures: make(chan ListenerFailure, 4)}
}

// Failures is a daemon-facing notification stream for unexpected active
// listener termination. It is intentionally read-only and bounded; a current
// listener can publish at most one terminal failure because Serve exits once.
func (m *Manager) Failures() <-chan ListenerFailure { return m.failures }

func buildRoutes(cfg config.Snapshot) (map[string]route, error) {
	certificates, err := certstore.New(cfg.Certificates)
	if err != nil {
		return nil, fmt.Errorf("certificate store: %w", err)
	}
	out := map[string]route{}
	for _, r := range cfg.Web {
		if !r.Enabled {
			continue
		}
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
		if domain == "" {
			return nil, fmt.Errorf("web rule %s has empty domain", r.ID)
		}
		u, err := url.Parse(strings.TrimSpace(r.Target))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("web rule %s has invalid target %q", r.ID, r.Target)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		target := u
		rp.Director = nil
		// Rewrite runs after removing hop-by-hop and client-supplied forwarding
		// headers, preventing spoofed client identity and Connection stripping.
		rp.Rewrite = func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			req.SetXForwarded()
		}
		rp.ErrorHandler = func(w http.ResponseWriter, req *http.Request, e error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		certID := strings.TrimSpace(r.Certificate)
		if r.HTTPS {
			certID, err = certificates.Resolve(certID, domain)
			if err != nil {
				return nil, fmt.Errorf("web rule %s certificate: %w", r.ID, err)
			}
		}
		if _, exists := out[domain]; exists {
			return nil, fmt.Errorf("duplicate web domain %s", domain)
		}
		out[domain] = route{Domain: domain, Target: u, Proxy: rp, HTTPS: r.HTTPS, CertID: certID}
	}
	return out, nil
}

func stripHostPort(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSuffix(h, ".")
	}
	// HTTP Host may be a bare DNS name with no port.
	return strings.TrimSuffix(host, ".")
}

func (m *Manager) findRoute(host string) (route, bool) {
	name := stripHostPort(host)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if r, ok := m.routes[name]; ok {
		return r, true
	}
	// TLS wildcards cover exactly one label, so there is at most one
	// possible wildcard key. Avoid allocating and sorting on every miss.
	if dot := strings.IndexByte(name, '.'); dot > 0 {
		if r, ok := m.routes["*"+name[dot:]]; ok {
			return r, true
		}
	}
	return route{}, false
}

func (m *Manager) handler(w http.ResponseWriter, req *http.Request) {
	r, ok := m.findRoute(req.Host)
	if !ok {
		http.NotFound(w, req)
		return
	}

	addr, addrErr := access.ClientAddr(req.RemoteAddr)
	m.mu.RLock()
	policy := m.accessPolicy
	recorder := m.accessRecorder
	m.mu.RUnlock()
	decision := access.Decision{Allowed: true, Reason: "disabled", PolicyMode: "disabled"}
	if addrErr != nil {
		if policy != nil && policy.Enabled {
			decision = access.Decision{Allowed: false, Reason: "invalid-source", PolicyMode: policy.Mode()}
		}
	} else if policy != nil {
		decision = policy.Evaluate(addr)
	}
	ipText := ""
	if addrErr == nil {
		ipText = addr.String()
	}
	if recorder != nil {
		recorder.Record(ipText, stripHostPort(req.Host), decision)
	}
	if !decision.Allowed {
		m.logAccessDenied(ipText, stripHostPort(req.Host), decision.Reason)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if r.HTTPS && req.TLS == nil {
		host := stripHostPort(req.Host)
		if host == "" {
			host = r.Domain
		}
		m.mu.RLock()
		httpsPort := m.publicHTTPSPort
		m.mu.RUnlock()
		if httpsPort <= 0 {
			httpsPort = config.DefaultHTTPSPort
		}
		if httpsPort != 443 {
			host = net.JoinHostPort(host, strconv.Itoa(httpsPort))
		}
		http.Redirect(w, req, "https://"+host+req.URL.RequestURI(), http.StatusPermanentRedirect)
		return
	}
	r.Proxy.ServeHTTP(w, req)
}

func (m *Manager) logAccessDenied(ip, host, reason string) {
	if m.log == nil {
		return
	}
	key := ip + "|" + host
	now := time.Now()
	m.mu.Lock()
	if current, exists := m.denyLogged[key]; exists && now.Before(current.last.Add(denyLogInterval)) {
		m.mu.Unlock()
		return
	}

	// Keep the throttle table strictly bounded without scanning it on an
	// attacker-controlled stream of unique IPv6 sources. Each successful log
	// gets a generation in a fixed ring. Old slots only delete the map entry if
	// their generation is still current for that key.
	m.denySeq++
	seq := m.denySeq
	if len(m.denyRing) == 0 {
		m.denyRing = make([]denyLogSlot, denyLogMaxEntries)
	}
	slot := m.denyRing[m.denyNext]
	if slot.key != "" {
		if current, ok := m.denyLogged[slot.key]; ok && current.seq == slot.seq {
			delete(m.denyLogged, slot.key)
		}
	}
	m.denyRing[m.denyNext] = denyLogSlot{key: key, seq: seq}
	m.denyNext = (m.denyNext + 1) % len(m.denyRing)
	m.denyLogged[key] = denyLogEntry{last: now, seq: seq}
	m.mu.Unlock()
	m.log.Warnf("access denied ip=%s host=%s reason=%s", ip, host, reason)
}

func sameCertificateFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && os.SameFile(a, b)
}

func (m *Manager) pruneCertificateCache(routes map[string]route) {
	active := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		if r.HTTPS && r.CertID != "" {
			active[r.CertID] = struct{}{}
		}
	}
	m.certMu.Lock()
	for certID := range m.certCache {
		if _, ok := active[certID]; !ok {
			delete(m.certCache, certID)
		}
	}
	m.certMu.Unlock()
}

func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r, ok := m.findRoute(hello.ServerName)
	if !ok || !r.HTTPS || r.CertID == "" {
		return nil, fmt.Errorf("no certificate configured for %s", hello.ServerName)
	}
	certPath := filepath.Join(m.homeDir, "certs", r.CertID, "fullchain.pem")
	keyPath := filepath.Join(m.homeDir, "certs", r.CertID, "privkey.pem")

	// stat(2) is deliberately kept on the handshake path so ACME renewals are
	// observed without a daemon reload. Cache hits take only the shared cache
	// lock; expensive PEM/key parsing is serialized only when the files change.
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate %s: %w", r.CertID, err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate %s: %w", r.CertID, err)
	}
	m.certMu.RLock()
	cached, cachedOK := m.certCache[r.CertID]
	if cachedOK && sameCertificateFile(cached.certInfo, certInfo) && sameCertificateFile(cached.keyInfo, keyInfo) {
		pair := cached.pair
		m.certMu.RUnlock()
		return pair, nil
	}
	m.certMu.RUnlock()

	m.certMu.Lock()
	defer m.certMu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		certInfo, err = os.Stat(certPath)
		if err != nil {
			return nil, fmt.Errorf("load certificate %s: %w", r.CertID, err)
		}
		keyInfo, err = os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load certificate %s: %w", r.CertID, err)
		}
		if cached, ok := m.certCache[r.CertID]; ok && sameCertificateFile(cached.certInfo, certInfo) && sameCertificateFile(cached.keyInfo, keyInfo) {
			return cached.pair, nil
		}

		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load certificate %s: %w", r.CertID, err)
		}
		certAfter, certErr := os.Stat(certPath)
		keyAfter, keyErr := os.Stat(keyPath)
		if certErr != nil || keyErr != nil || !sameCertificateFile(certInfo, certAfter) || !sameCertificateFile(keyInfo, keyAfter) {
			continue
		}
		entry := certificateCacheEntry{pair: &pair, certInfo: certAfter, keyInfo: keyAfter}
		m.certCache[r.CertID] = entry
		return entry.pair, nil
	}
	return nil, fmt.Errorf("load certificate %s: certificate files changed while loading", r.CertID)
}

func (m *Manager) RefreshAccessPolicy(main config.Main) error {
	m.mu.RLock()
	generation := m.runtimeGeneration
	m.mu.RUnlock()
	_, err := m.RefreshAccessPolicyGeneration(main, generation)
	return err
}

// RefreshAccessPolicyGeneration only publishes the parsed policy when the
// caller still belongs to the runtime generation it was started for. The
// generation comparison and policy publication share m.mu, so an old async
// refresh cannot race a newer ApplyGeneration commit and overwrite its policy.
func (m *Manager) RefreshAccessPolicyGeneration(main config.Main, generation uint64) (bool, error) {
	policy, err := access.LoadPolicy(main, m.homeDir)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	if m.runtimeGeneration != generation {
		m.mu.Unlock()
		return false, nil
	}
	m.accessPolicy = policy
	recorder := m.accessRecorder
	m.mu.Unlock()
	if recorder != nil {
		recorder.ReevaluateCurrent(policy)
		m.ensureAccessGeoAsync(recorder)
	}
	return true, nil
}

// AdoptGeneration moves an unchanged last-known-good runtime to a fresh worker
// generation after a candidate reload was rejected. No route/listener/policy
// state changes; only stale async workers lose commit authority.
func (m *Manager) AdoptGeneration(generation uint64) {
	m.mu.Lock()
	m.runtimeGeneration = generation
	m.mu.Unlock()
}

// ensureAccessGeoAsync keeps GeoIP display metadata out of request/CLI hot
// paths. Region cache files are fingerprinted with stat(2); CIDR parsing only
// happens in the long-lived daemon when those files change. Until the first
// resolver is ready, recent rows safely show UNKNOWN and are backfilled later.
func (m *Manager) ensureAccessGeoAsync(recorder *access.Recorder) {
	fingerprint := access.GeoFingerprint(m.homeDir)
	if fingerprint == "" || recorder == nil {
		return
	}

	m.mu.Lock()
	if m.accessGeo != nil {
		geo := m.accessGeo
		m.mu.Unlock()
		recorder.SetGeoResolver(geo)
		m.mu.Lock()
	}
	if fingerprint == m.accessGeoFingerprint || fingerprint == m.accessGeoLoading {
		m.mu.Unlock()
		return
	}
	m.accessGeoLoading = fingerprint
	m.mu.Unlock()

	go func(expected string) {
		geo := access.LoadGeoResolver(m.homeDir)
		actual := access.GeoFingerprint(m.homeDir)
		if actual != expected {
			m.mu.Lock()
			if m.accessGeoLoading == expected {
				m.accessGeoLoading = ""
			}
			current := m.accessRecorder
			m.mu.Unlock()
			if current != nil {
				m.ensureAccessGeoAsync(current)
			}
			return
		}

		m.mu.Lock()
		m.accessGeo = geo
		m.accessGeoFingerprint = expected
		if m.accessGeoLoading == expected {
			m.accessGeoLoading = ""
		}
		current := m.accessRecorder
		m.mu.Unlock()
		if current != nil {
			current.SetGeoResolver(geo)
		}
	}(fingerprint)
}

func (m *Manager) Apply(ctx context.Context, cfg config.Snapshot) (Status, error) {
	return m.ApplyGeneration(ctx, cfg, 0)
}

func (m *Manager) ApplyGeneration(ctx context.Context, cfg config.Snapshot, generation uint64) (Status, error) {
	prepared, err := m.PrepareGeneration(ctx, cfg, generation)
	if err != nil {
		m.mu.RLock()
		st := m.last
		m.mu.RUnlock()
		return st, err
	}
	return m.CommitPrepared(ctx, prepared), nil
}

// PrepareGeneration builds routes/policy/recorder and pre-binds replacement
// listeners without publishing any new runtime pointer or retiring the current
// listeners. Phase 4G uses this prepare boundary so Firewall can accept the
// same candidate before Proxy and Config are committed.
func (m *Manager) PrepareGeneration(ctx context.Context, cfg config.Snapshot, generation uint64) (*PreparedRuntime, error) {
	routes, err := buildRoutes(cfg)
	if err != nil {
		m.applyFailureStatus(cfg, err)
		return nil, err
	}
	policy, err := access.LoadPolicy(cfg.Main, m.homeDir)
	if err != nil {
		m.applyFailureStatus(cfg, err)
		return nil, err
	}
	needHTTPS, needHTTP := false, false
	for _, r := range routes {
		if r.HTTPS {
			needHTTPS = true
			// HTTPS public services also need the internal HTTP listener so
			// WAN :80 can return a canonical HTTP -> HTTPS redirect.
			needHTTP = true
		} else {
			needHTTP = true
		}
	}

	httpsCandidate, err := m.prepareHTTPS(needHTTPS, cfg.Main.ProxyHTTPSPort)
	if err != nil {
		m.applyFailureStatus(cfg, err)
		return nil, err
	}
	httpCandidate, err := m.prepareHTTP(needHTTP, cfg.Main.ProxyHTTPPort)
	if err != nil {
		m.abortListenerCandidate(httpsCandidate)
		m.applyFailureStatus(cfg, err)
		return nil, err
	}

	// Re-open the runtime recent-access snapshot on reload. Current-policy
	// annotations are refreshed from the policy already parsed above; GeoIP is
	// attached from the daemon cache and rebuilt asynchronously only when region
	// cache metadata changes.
	recorder := access.NewRecorder("")
	m.mu.RLock()
	cachedGeo := m.accessGeo
	m.mu.RUnlock()
	if cachedGeo != nil {
		recorder.SetGeoResolver(cachedGeo)
	}
	recorder.ReevaluateCurrent(policy)

	return &PreparedRuntime{
		cfg:            cfg,
		generation:     generation,
		routes:         routes,
		policy:         policy,
		recorder:       recorder,
		httpsCandidate: httpsCandidate,
		httpCandidate:  httpCandidate,
	}, nil
}

// AbortPrepared closes only listeners pre-bound for a candidate that never
// committed. Reused current listeners are never touched.
func (m *Manager) AbortPrepared(prepared *PreparedRuntime) {
	if prepared == nil {
		return
	}
	m.abortListenerCandidate(prepared.httpsCandidate)
	m.abortListenerCandidate(prepared.httpCandidate)
}

// CommitPrepared publishes a previously prepared runtime. There are no
// candidate-validation or listener-bind failure points left here.
func (m *Manager) CommitPrepared(ctx context.Context, prepared *PreparedRuntime) Status {
	if prepared == nil {
		err := errors.New("nil prepared proxy runtime")
		return m.applyFailureStatus(config.Snapshot{}, err)
	}

	cfg := prepared.cfg
	httpsCandidate := prepared.httpsCandidate
	httpCandidate := prepared.httpCandidate

	m.mu.Lock()
	oldHTTPSLn, oldHTTPSSLn := m.httpsListener, m.httpListener
	oldHTTPSSrv, oldHTTPSrv := m.httpsServer, m.httpServer

	m.routes = prepared.routes
	m.publicHTTPSPort = cfg.Main.HTTPSPort
	m.accessPolicy = prepared.policy
	m.accessRecorder = prepared.recorder
	m.activeCfg = cfg
	m.hasActiveCfg = true
	m.runtimeGeneration = prepared.generation

	if !httpsCandidate.need {
		m.httpsListener = nil
		m.httpsServer = nil
		m.httpsPort = 0
	} else if !httpsCandidate.reuse {
		m.httpsListener = httpsCandidate.ln
		m.httpsServer = httpsCandidate.srv
		m.httpsPort = httpsCandidate.port
	}
	if !httpCandidate.need {
		m.httpListener = nil
		m.httpServer = nil
		m.httpPort = 0
	} else if !httpCandidate.reuse {
		m.httpListener = httpCandidate.ln
		m.httpServer = httpCandidate.srv
		m.httpPort = httpCandidate.port
	}
	m.mu.Unlock()
	m.pruneCertificateCache(prepared.routes)

	// Only after the atomic runtime publication do new listeners begin serving.
	// Retiring an old listener is post-commit cleanup; failure to drain it does
	// not roll back a runtime that is already live, so force-close and log.
	if httpsCandidate.need && !httpsCandidate.reuse {
		m.serveHTTPS(httpsCandidate)
	}
	if httpCandidate.need && !httpCandidate.reuse {
		m.serveHTTP(httpCandidate)
	}
	if oldHTTPSSrv != nil && (!httpsCandidate.need || !httpsCandidate.reuse) {
		m.retireServer(ctx, "HTTPS", oldHTTPSSrv, oldHTTPSLn)
	}
	if oldHTTPSrv != nil && (!httpCandidate.need || !httpCandidate.reuse) {
		m.retireServer(ctx, "HTTP", oldHTTPSrv, oldHTTPSSLn)
	}

	m.ensureAccessGeoAsync(prepared.recorder)
	st := m.status(cfg, nil)
	m.writeStatus(st)
	return st
}

func (m *Manager) applyFailureStatus(candidate config.Snapshot, err error) Status {
	m.mu.RLock()
	cfg := candidate
	if m.hasActiveCfg {
		cfg = m.activeCfg
	}
	m.mu.RUnlock()
	st := m.status(cfg, err)
	m.writeStatus(st)
	return st
}

func (m *Manager) prepareHTTPS(need bool, port int) (listenerCandidate, error) {
	c := listenerCandidate{need: need, port: port}
	m.mu.RLock()
	oldLn, oldPort := m.httpsListener, m.httpsPort
	m.mu.RUnlock()
	if !need || port <= 0 {
		return c, nil
	}
	if oldLn != nil && oldPort == port {
		c.reuse = true
		return c, nil
	}
	rawLn, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		return c, fmt.Errorf("listen HTTPS %d: %w", port, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(m.handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.getCertificate}, ReadHeaderTimeout: 15 * time.Second}
	c.ln = tls.NewListener(rawLn, srv.TLSConfig)
	c.srv = srv
	return c, nil
}

func (m *Manager) prepareHTTP(need bool, port int) (listenerCandidate, error) {
	c := listenerCandidate{need: need, port: port}
	m.mu.RLock()
	oldLn, oldPort := m.httpListener, m.httpPort
	m.mu.RUnlock()
	if !need || port <= 0 {
		return c, nil
	}
	if oldLn != nil && oldPort == port {
		c.reuse = true
		return c, nil
	}
	ln, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		return c, fmt.Errorf("listen HTTP %d: %w", port, err)
	}
	c.ln = ln
	c.srv = &http.Server{Handler: http.HandlerFunc(m.handler), ReadHeaderTimeout: 15 * time.Second}
	return c, nil
}

func (m *Manager) abortListenerCandidate(c listenerCandidate) {
	if !c.reuse && c.ln != nil {
		_ = c.ln.Close()
	}
}

func (m *Manager) serveHTTPS(c listenerCandidate) {
	go func() {
		if err := c.srv.Serve(c.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.listenerFailed("https", c, err)
		}
	}()
	if m.log != nil {
		m.log.Infof("Web HTTPS internal listener %d enabled", c.port)
	}
}

func (m *Manager) serveHTTP(c listenerCandidate) {
	go func() {
		if err := c.srv.Serve(c.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.listenerFailed("http", c, err)
		}
	}()
	if m.log != nil {
		m.log.Infof("Web HTTP internal listener %d enabled", c.port)
	}
}

func (m *Manager) listenerFailed(protocol string, c listenerCandidate, err error) {
	if err == nil {
		return
	}

	active := false
	var cfg config.Snapshot
	m.mu.Lock()
	switch protocol {
	case "https":
		if m.httpsServer == c.srv {
			m.httpsServer = nil
			m.httpsListener = nil
			m.httpsPort = 0
			active = true
		}
	case "http":
		if m.httpServer == c.srv {
			m.httpServer = nil
			m.httpListener = nil
			m.httpPort = 0
			active = true
		}
	}
	if active && m.hasActiveCfg {
		cfg = m.activeCfg
	}
	m.mu.Unlock()

	// A retired listener can finish after a replacement has already committed.
	// Ignore that stale terminal result; only the currently published listener
	// is allowed to affect runtime truth or request daemon recovery.
	if !active {
		return
	}

	st := m.status(cfg, err)
	m.writeStatus(st)
	if m.log != nil {
		m.log.Errorf("%s proxy listener stopped unexpectedly: %v", strings.ToUpper(protocol), err)
	}

	failure := ListenerFailure{Protocol: protocol, Port: c.port, Err: err}
	select {
	case m.failures <- failure:
	default:
		// At most one terminal failure is emitted per listener. If both HTTP and
		// HTTPS fail at once and the daemon is momentarily busy, the next Proxy
		// retry reconciles both listeners from desired state, so dropping an
		// additional notification cannot leave a distinct recovery obligation.
	}
}

func (m *Manager) retireServer(ctx context.Context, name string, srv *http.Server, ln net.Listener) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := srv.Shutdown(c)
	cancel()
	if err != nil {
		_ = srv.Close()
	}
	if err != nil && m.log != nil {
		m.log.Warnf("retire %s proxy listener: %v", name, err)
	}
	if ln != nil {
		_ = ln.Close()
	}
	if m.log != nil {
		m.log.Infof("Web %s internal listener stopped", name)
	}
}

func (m *Manager) closeHTTPS(ctx context.Context) error {
	m.mu.Lock()
	srv := m.httpsServer
	ln := m.httpsListener
	m.httpsServer = nil
	m.httpsListener = nil
	m.httpsPort = 0
	m.mu.Unlock()
	if srv != nil {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(c); err != nil {
			_ = srv.Close()
			return err
		}
	}
	if ln != nil {
		_ = ln.Close()
	}
	if (srv != nil || ln != nil) && m.log != nil {
		m.log.Infof("Web HTTPS internal listener stopped")
	}
	return nil
}
func (m *Manager) closeHTTP(ctx context.Context) error {
	m.mu.Lock()
	srv := m.httpServer
	ln := m.httpListener
	m.httpServer = nil
	m.httpListener = nil
	m.httpPort = 0
	m.mu.Unlock()
	if srv != nil {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(c); err != nil {
			_ = srv.Close()
			return err
		}
	}
	if ln != nil {
		_ = ln.Close()
	}
	if (srv != nil || ln != nil) && m.log != nil {
		m.log.Infof("Web HTTP internal listener stopped")
	}
	return nil
}
func (m *Manager) Close(ctx context.Context) error {
	e1 := m.closeHTTPS(ctx)
	e2 := m.closeHTTP(ctx)
	m.mu.RLock()
	recorder := m.accessRecorder
	m.mu.RUnlock()
	if recorder != nil {
		// All listeners are drained above, so no new request can race this final
		// bounded recent-access flush during daemon shutdown.
		recorder.Flush()
	}
	m.mu.Lock()
	st := m.last
	st.HTTPSListening = false
	st.HTTPListening = false
	st.HTTPSPort = 0
	st.HTTPPort = 0
	m.last = st
	m.mu.Unlock()
	m.writeStatus(st)
	if e1 != nil {
		return e1
	}
	return e2
}

func (m *Manager) status(cfg config.Snapshot, err error) Status {
	st := Status{APIVersion: 1, OK: err == nil, Version: m.version, Phase: Phase, Configured: len(cfg.Web), Domains: []string{}, AccessEnabled: cfg.Main.AccessEnabled, AccessRegion: cfg.Main.AccessRegion}
	for _, r := range cfg.Web {
		if r.Enabled {
			st.Enabled++
			st.Domains = append(st.Domains, r.Domain)
		}
	}
	sort.Strings(st.Domains)
	m.mu.RLock()
	st.HTTPSListening = m.httpsListener != nil
	st.HTTPListening = m.httpListener != nil
	st.HTTPSPort = m.httpsPort
	st.HTTPPort = m.httpPort
	m.mu.RUnlock()
	if err != nil {
		st.Error = err.Error()
	}
	m.mu.Lock()
	m.last = st
	m.mu.Unlock()
	return st
}

func BuildStatus(version string, cfg config.Snapshot) Status {
	_, err := buildRoutes(cfg)
	st := Status{APIVersion: 1, OK: err == nil, Version: version, Phase: Phase, Configured: len(cfg.Web), Domains: []string{}, AccessEnabled: cfg.Main.AccessEnabled, AccessRegion: cfg.Main.AccessRegion}
	for _, r := range cfg.Web {
		if r.Enabled {
			st.Enabled++
			st.Domains = append(st.Domains, r.Domain)
			if r.HTTPS {
				st.HTTPSPort = cfg.Main.ProxyHTTPSPort
				st.HTTPPort = cfg.Main.ProxyHTTPPort
			} else {
				st.HTTPPort = cfg.Main.ProxyHTTPPort
			}
		}
	}
	sort.Strings(st.Domains)
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

func (m *Manager) writeStatus(st Status) {
	path := m.StatusPath
	if path == "" {
		path = DefaultStatusPath
	}
	if err := runtimefile.WriteJSONAtomic(path, st, 0o600); err != nil && m.log != nil {
		m.log.Errorf("write proxy status: %v", err)
	}
}

func ReadStatus(path, version string) (Status, error) {
	if path == "" {
		path = DefaultStatusPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return Status{}, err
	}
	st.Version = version
	return st, nil
}
