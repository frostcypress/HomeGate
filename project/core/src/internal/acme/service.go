package acme

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"homegate.local/homegate/internal/acmeca"
	"homegate.local/homegate/internal/certstore"
	"homegate.local/homegate/internal/config"
	"homegate.local/homegate/internal/dnsprovider"
)

const Phase = "acme"

type Logger interface {
	Infof(string, ...any)
	Errorf(string, ...any)
}

type TXTWaiter interface {
	Wait(context.Context, string, string) error
}

type ProviderFactory = dnsprovider.RecordFactory

type Service struct {
	HomeDir                 string
	HTTP                    HTTPDoer
	Provider                ProviderFactory
	TXT                     TXTWaiter
	Log                     Logger
	Now                     func() time.Time
	Sleep                   func(context.Context, time.Duration) error
	IssueTimeout            time.Duration
	DirectoryForEnvironment func(string) string
	// Commit, when set by the daemon, linearizes certificate publication against
	// runtime generation changes. Manual CLI calls leave it nil and remain fully
	// synchronous. The callback returns committed=false when this worker became
	// stale before its final side effect.
	Commit func(func() error) (committed bool, err error)
}

type CertificateStatus struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Source        string   `json:"source"`
	CA            string   `json:"ca,omitempty"`
	Environment   string   `json:"environment"`
	Domains       []string `json:"domains"`
	Enabled       bool     `json:"enabled"`
	Exists        bool     `json:"exists"`
	Expires       string   `json:"expires,omitempty"`
	Days          int      `json:"days"`
	Renew         bool     `json:"renew"`
	RenewState    string   `json:"renew_state,omitempty"`
	RenewError    string   `json:"renew_error,omitempty"`
	LastRenewAt   string   `json:"last_renew_at,omitempty"`
	IdentityValid *bool    `json:"identity_valid,omitempty"`
	IdentityError string   `json:"identity_error,omitempty"`
}

type StatusReport struct {
	APIVersion   int                 `json:"api_version"`
	OK           bool                `json:"ok"`
	Version      string              `json:"version"`
	Phase        string              `json:"phase"`
	Certificates []CertificateStatus `json:"certificates"`
	Error        string              `json:"error,omitempty"`
}

type IssueReport struct {
	APIVersion   int      `json:"api_version"`
	OK           bool     `json:"ok"`
	Version      string   `json:"version"`
	Phase        string   `json:"phase"`
	Certificate  string   `json:"certificate"`
	Domains      []string `json:"domains,omitempty"`
	Expires      string   `json:"expires,omitempty"`
	Error        string   `json:"error,omitempty"`
	ErrorKind    string   `json:"error_kind,omitempty"`
	Retryable    bool     `json:"retryable,omitempty"`
	ProviderCode string   `json:"provider_code,omitempty"`
}

type RenewReport struct {
	APIVersion int           `json:"api_version"`
	OK         bool          `json:"ok"`
	Version    string        `json:"version"`
	Phase      string        `json:"phase"`
	Results    []IssueReport `json:"results"`
	Error      string        `json:"error,omitempty"`
}

func NewService(homeDir string, log Logger) Service {
	if strings.TrimSpace(homeDir) == "" {
		homeDir = "/etc/homegate"
	}
	return Service{
		HomeDir:  homeDir,
		Provider: dnsprovider.NewRecord,
		TXT:      PublicTXTWaiter{},
		Log:      log,
		Now:      time.Now,
		Sleep:    sleepContext,
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type renewalAttempt struct {
	AttemptedAt string `json:"attempted_at"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
}

func (s Service) renewalAttemptPath(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id {
		return ""
	}
	home := filepath.Clean(strings.TrimSpace(s.HomeDir))
	if home == "." || home == "" || home == "/etc/homegate" {
		return filepath.Join("/var/run/homegate/acme-renew", id+".json")
	}
	// Tests and non-default embeddings keep runtime state inside their private
	// HomeDir instead of touching the host /var/run tree.
	return filepath.Join(home, "runtime", "acme-renew", id+".json")
}

func (s Service) readRenewalAttempt(id string) (renewalAttempt, bool) {
	path := s.renewalAttemptPath(id)
	if path == "" {
		return renewalAttempt{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return renewalAttempt{}, false
	}
	var st renewalAttempt
	if json.Unmarshal(b, &st) != nil || strings.TrimSpace(st.AttemptedAt) == "" {
		return renewalAttempt{}, false
	}
	return st, true
}

func compactRenewalError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

func (s Service) writeRenewalAttempt(id string, ok bool) error {
	return s.writeRenewalAttemptDetail(id, ok, "")
}

func (s Service) writeRenewalAttemptDetail(id string, ok bool, errorText string) error {
	path := s.renewalAttemptPath(id)
	if path == "" {
		return fmt.Errorf("invalid certificate id for renewal state")
	}
	st := renewalAttempt{AttemptedAt: s.now().UTC().Format(time.RFC3339), OK: ok, Error: strings.TrimSpace(errorText)}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}

func (s Service) rememberRenewalAttempt(id string, ok bool, attemptErr error) {
	if attemptErr != nil && errors.Is(attemptErr, context.Canceled) {
		return
	}
	if err := s.writeRenewalAttemptDetail(id, ok, compactRenewalError(attemptErr)); err != nil && s.Log != nil {
		s.Log.Errorf("certificate %s renewal runtime status write failed: %v", id, err)
	}
}

func (s Service) accountKeyPath() string { return filepath.Join(s.HomeDir, "acme", "account.key") }
func (s Service) accountStatePath(directory string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(directory)))
	return filepath.Join(s.HomeDir, "acme", "accounts", fmt.Sprintf("%x.json", h[:]))
}
func (s Service) certPaths(id string) (string, string) {
	base := filepath.Join(s.HomeDir, "certs", id)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

func challengeHost(domain, zone string) (string, error) {
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*.")
	z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if d == "" || z == "" {
		return "", fmt.Errorf("ACME domain/zone is empty")
	}
	if d == z {
		return "_acme-challenge", nil
	}
	suffix := "." + z
	if !strings.HasSuffix(d, suffix) {
		return "", fmt.Errorf("domain %s is not inside zone %s", domain, zone)
	}
	rel := strings.TrimSuffix(d, suffix)
	return "_acme-challenge." + rel, nil
}

func certExpiry(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func (s Service) sleeper(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	return sleepContext(ctx, d)
}

func (s Service) NeedsRenew(cert config.Certificate) bool {
	if strings.EqualFold(strings.TrimSpace(cert.Source), "local") {
		return false
	}
	path, _ := s.certPaths(cert.ID)
	exp, err := certExpiry(path)
	if err != nil {
		return true
	}
	days := cert.RenewDays
	if days <= 0 {
		days = config.DefaultRenewDays
	}
	return exp.Sub(s.now()) < time.Duration(days)*24*time.Hour
}

func FindCertificate(cfg config.Snapshot, id string) (config.Certificate, error) {
	for _, c := range cfg.Certificates {
		if c.ID == id {
			return c, nil
		}
	}
	return config.Certificate{}, fmt.Errorf("certificate not found: %s", id)
}

func (s Service) Status(version string, cfg config.Snapshot) StatusReport {
	out := StatusReport{APIVersion: 1, OK: true, Version: version, Phase: Phase, Certificates: make([]CertificateStatus, 0, len(cfg.Certificates))}
	for _, c := range cfg.Certificates {
		source := strings.ToLower(strings.TrimSpace(c.Source))
		if source == "" {
			source = "acme"
		}
		environment := strings.ToLower(strings.TrimSpace(c.Environment))
		if environment == "" {
			environment = config.DefaultCertificateEnvironment
		}
		ca := strings.ToLower(strings.TrimSpace(c.CA))
		if ca == "" && source != "local" {
			ca = "letsencrypt"
		}
		st := CertificateStatus{ID: c.ID, Name: c.Name, Source: source, CA: ca, Environment: environment, Domains: append([]string{}, c.Domains...), Enabled: c.Enabled, Renew: c.Enabled && s.NeedsRenew(c)}
		path, _ := s.certPaths(c.ID)
		if chain, err := os.ReadFile(path); err == nil {
			if exp, parseErr := certExpiryPEM(chain); parseErr == nil {
				st.Exists = true
				st.Expires = exp.UTC().Format(time.RFC3339)
				st.Days = int(exp.Sub(s.now()).Hours() / 24)
				valid := true
				if identityErr := certstore.ValidatePEMIdentities(chain, c.Domains); identityErr != nil {
					valid = false
					st.IdentityError = identityErr.Error()
				}
				st.IdentityValid = &valid
			}
		}
		if attempt, ok := s.readRenewalAttempt(c.ID); ok {
			st.LastRenewAt = attempt.AttemptedAt
			// A failed attempt is user-actionable only while this same certificate
			// is still actually due. A later successful renewal or external
			// replacement naturally clears the warning because Renew becomes false.
			if st.Renew && !attempt.OK {
				st.RenewState = "failed"
				st.RenewError = attempt.Error
			}
		}
		out.Certificates = append(out.Certificates, st)
	}
	return out
}

func issueError(version, id string, domains []string, err error) IssueReport {
	r := IssueReport{APIVersion: 1, OK: false, Version: version, Phase: Phase, Certificate: id, Domains: append([]string{}, domains...), Error: err.Error()}
	kind, retryable, code := dnsprovider.ErrorDetails(err)
	if kind == dnsprovider.ErrorUnknown {
		var netErr net.Error
		text := strings.ToLower(strings.TrimSpace(err.Error()))
		switch {
		case errors.As(err, &netErr):
			kind = dnsprovider.ErrorNetworkUnavailable
			retryable = true
		case strings.Contains(text, "http 429"):
			kind = dnsprovider.ErrorRateLimit
			retryable = true
		case strings.Contains(text, "http 5"):
			kind = dnsprovider.ErrorTemporary
			retryable = true
		}
	}
	if kind != "" && kind != dnsprovider.ErrorUnknown {
		r.ErrorKind = string(kind)
	}
	r.Retryable = retryable
	r.ProviderCode = code
	return r
}

func (s Service) issueLocked(ctx context.Context, version string, cfg config.Snapshot, cc config.Certificate) (IssueReport, error) {
	fail := func(err error) (IssueReport, error) {
		s.rememberRenewalAttempt(cc.ID, false, err)
		return issueError(version, cc.ID, cc.Domains, err), err
	}
	if !cc.Enabled {
		return fail(errors.New("certificate is disabled"))
	}
	if strings.EqualFold(strings.TrimSpace(cc.Source), "local") {
		return fail(errors.New("local certificate is not ACME-managed"))
	}
	if strings.TrimSpace(cc.ID) == "" {
		return fail(errors.New("certificate id is empty"))
	}
	if len(cc.Domains) == 0 {
		return fail(errors.New("certificate has no domains"))
	}
	if strings.TrimSpace(cc.Zone) == "" {
		return fail(errors.New("certificate zone is empty"))
	}
	account, ok := cfg.Accounts[cc.Account]
	if !ok {
		return fail(fmt.Errorf("DNS account not found: %s", cc.Account))
	}
	factory := s.Provider
	if factory == nil {
		factory = dnsprovider.NewRecord
	}
	provider, err := factory(account)
	if err != nil {
		return fail(err)
	}
	for _, d := range cc.Domains {
		if _, err := challengeHost(d, cc.Zone); err != nil {
			return fail(err)
		}
	}

	h := s.HTTP
	// ACME CA and environment are certificate-resource properties. They must
	// never redirect renewals for unrelated certificate resources.
	selection, err := acmeca.Resolve(cc.CA, cc.Environment)
	if err != nil {
		return fail(err)
	}
	directory := selection.Directory
	// Retained only for deterministic pre-1.1 unit/integration injection. Normal
	// runtime always resolves from the CA catalog above.
	if s.DirectoryForEnvironment != nil {
		directory = strings.TrimSpace(s.DirectoryForEnvironment(cc.Environment))
	}
	if directory == "" {
		return fail(errors.New("ACME directory is empty"))
	}
	ac, err := newClient(ctx, directory, s.accountKeyPath(), h)
	if err != nil {
		return fail(err)
	}
	ac.accountStatePath = s.accountStatePath(directory)
	email := cc.Email
	if email == "" {
		email = cfg.Main.ACMEEmail
	}
	if err := ac.ensureAccount(ctx, email); err != nil {
		return fail(err)
	}

	ids := make([]map[string]string, 0, len(cc.Domains))
	for _, d := range cc.Domains {
		ids = append(ids, map[string]string{"type": "dns", "value": strings.TrimSpace(d)})
	}
	var ord order
	head, err := ac.postJSONHeader(ctx, ac.dir.NewOrder, map[string]any{"identifiers": ids}, &ord)
	if err != nil {
		return fail(err)
	}
	orderURL := head.Get("Location")
	if orderURL == "" {
		return fail(errors.New("ACME did not return Order Location"))
	}

	waiter := s.TXT
	if waiter == nil {
		waiter = PublicTXTWaiter{}
	}
	for _, authURL := range ord.Authorizations {
		var auth authorization
		if err := ac.postAsGet(ctx, authURL, &auth); err != nil {
			return fail(err)
		}
		if auth.Status == "valid" {
			continue
		}
		var ch *challenge
		for i := range auth.Challenges {
			if auth.Challenges[i].Type == "dns-01" {
				ch = &auth.Challenges[i]
				break
			}
		}
		if ch == nil {
			return fail(errors.New("ACME authorization has no dns-01 challenge"))
		}
		domain := auth.Identifier.Value
		if auth.Wildcard {
			domain = "*." + domain
		}
		host, err := challengeHost(domain, cc.Zone)
		if err != nil {
			return fail(err)
		}
		keyAuth := ch.Token + "." + jwkThumbprint(ac.key)
		digest := sha256.Sum256([]byte(keyAuth))
		txt := b64raw.EncodeToString(digest[:])

		challengeErr := func() error {
			if _, err := provider.Upsert(ctx, cc.Zone, host, "TXT", txt, 600); err != nil {
				return fmt.Errorf("create ACME TXT: %w", err)
			}
			cleanup := func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := provider.Delete(cleanupCtx, cc.Zone, host, "TXT", txt); err != nil && s.Log != nil {
					s.Log.Errorf("ACME TXT cleanup %s: %v", dnsprovider.FullDomain(cc.Zone, host), err)
				}
			}
			defer cleanup()
			fqdn := dnsprovider.FullDomain(cc.Zone, host)
			if err := waiter.Wait(ctx, fqdn, txt); err != nil {
				return err
			}
			if err := ac.postJSON(ctx, ch.URL, map[string]any{}, nil); err != nil {
				return err
			}
			for i := 0; i < 30; i++ {
				if err := s.sleeper(ctx, 3*time.Second); err != nil {
					return err
				}
				if err := ac.postAsGet(ctx, authURL, &auth); err != nil {
					continue
				}
				if auth.Status == "valid" {
					return nil
				}
				if auth.Status == "invalid" {
					return fmt.Errorf("ACME domain validation failed: %s", domain)
				}
			}
			return fmt.Errorf("ACME domain validation timeout: %s", domain)
		}()
		if challengeErr != nil {
			return fail(challengeErr)
		}
	}

	certPath, keyPath := s.certPaths(cc.ID)
	certKey, keyPEM, publishKey, err := loadCertificateKey(keyPath)
	if err != nil {
		return fail(err)
	}
	csr := x509.CertificateRequest{Subject: pkix.Name{CommonName: cc.Domains[0]}, DNSNames: cc.Domains, SignatureAlgorithm: x509.ECDSAWithSHA256}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csr, certKey)
	if err != nil {
		return fail(err)
	}
	if err := ac.postJSON(ctx, ord.Finalize, map[string]string{"csr": b64raw.EncodeToString(csrDER)}, &ord); err != nil {
		return fail(err)
	}
	for i := 0; i < 40; i++ {
		if ord.Status == "valid" && ord.Certificate != "" {
			break
		}
		if ord.Status == "invalid" {
			return fail(fmt.Errorf("ACME order invalid: %v", ord.Error))
		}
		if err := s.sleeper(ctx, 3*time.Second); err != nil {
			return fail(err)
		}
		if err := ac.postAsGet(ctx, orderURL, &ord); err != nil {
			continue
		}
	}
	if ord.Certificate == "" {
		return fail(errors.New("ACME did not return certificate URL"))
	}
	chain, err := ac.postAsGetRaw(ctx, ord.Certificate)
	if err != nil {
		return fail(err)
	}
	var exp time.Time
	publish := func() error {
		var publishErr error
		exp, publishErr = publishCertificatePair(certPath, keyPath, chain, keyPEM, publishKey, cc.Domains)
		return publishErr
	}
	if s.Commit != nil {
		committed, commitErr := s.Commit(publish)
		if commitErr != nil {
			return fail(commitErr)
		}
		if !committed {
			return fail(context.Canceled)
		}
	} else if err := publish(); err != nil {
		return fail(err)
	}
	report := IssueReport{APIVersion: 1, OK: true, Version: version, Phase: Phase, Certificate: cc.ID, Domains: append([]string{}, cc.Domains...), Expires: exp.UTC().Format(time.RFC3339)}
	if s.Log != nil {
		s.Log.Infof("certificate %s issued/renewed expires=%s", cc.ID, report.Expires)
	}
	s.rememberRenewalAttempt(cc.ID, true, nil)
	return report, nil
}

func (s Service) issueTimeout() time.Duration {
	if s.IssueTimeout > 0 {
		return s.IssueTimeout
	}
	return 12 * time.Minute
}

func (s Service) Issue(ctx context.Context, version string, cfg config.Snapshot, cc config.Certificate) (IssueReport, error) {
	if strings.TrimSpace(cc.ID) == "" {
		err := errors.New("certificate id is empty")
		return issueError(version, cc.ID, cc.Domains, err), err
	}
	release, err := s.acquireCertificateLock(ctx, cc.ID)
	if err != nil {
		return issueError(version, cc.ID, cc.Domains, err), err
	}
	defer release()
	return s.issueLocked(ctx, version, cfg, cc)
}

func (s Service) RenewDue(ctx context.Context, version string, cfg config.Snapshot) RenewReport {
	r := RenewReport{APIVersion: 1, OK: true, Version: version, Phase: Phase, Results: []IssueReport{}}
	for _, c := range cfg.Certificates {
		if !c.Enabled || !s.NeedsRenew(c) {
			continue
		}

		certCtx, cancel := context.WithTimeout(ctx, s.issueTimeout())
		release, err := s.acquireCertificateLock(certCtx, c.ID)
		if err != nil {
			cancel()
			r.Results = append(r.Results, issueError(version, c.ID, c.Domains, err))
			r.OK = false
			if ctx.Err() != nil {
				break
			}
			continue
		}

		// Another process may have renewed this certificate while this worker
		// waited for the cross-process lock. Re-check after acquiring it so an
		// automatic cycle never creates a duplicate ACME order.
		if !s.NeedsRenew(c) {
			release()
			cancel()
			continue
		}

		one, err := s.issueLocked(certCtx, version, cfg, c)
		release()
		cancel()
		r.Results = append(r.Results, one)
		if err != nil {
			r.OK = false
		}
		if ctx.Err() != nil {
			break
		}
	}
	if !r.OK {
		r.Error = "one or more certificate renewals failed"
	}
	return r
}

// PublicTXTWaiter preserves the r6 propagation strategy: require the exact TXT
// value to be visible from at least one independent public recursive resolver.
type PublicTXTWaiter struct {
	Servers []string
	Timeout time.Duration
	Poll    time.Duration
}

func (w PublicTXTWaiter) Wait(ctx context.Context, fqdn, value string) error {
	servers := w.Servers
	if len(servers) == 0 {
		servers = []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"}
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	poll := w.Poll
	if poll <= 0 {
		poll = 8 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, server := range servers {
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 4 * time.Second}
				return d.DialContext(ctx, "udp", server)
			}}
			vals, err := r.LookupTXT(ctx, fqdn)
			if err == nil {
				for _, v := range vals {
					if v == value {
						return nil
					}
				}
			}
		}
		if err := sleepContext(ctx, poll); err != nil {
			return err
		}
	}
	return dnsprovider.NewError("", "dns01.propagation", dnsprovider.ErrorPropagationPending, "", fmt.Sprintf("TXT propagation timeout: %s", fqdn), true, nil)
}
