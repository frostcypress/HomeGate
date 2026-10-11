package dnsprovider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	aliyunEndpoint       = "https://alidns.aliyuncs.com/"
	aliyunRequestTimeout = 20 * time.Second
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type AliyunProvider struct {
	AccessKeyID     string
	AccessKeySecret string
	Client          HTTPDoer
	Endpoint        string
	Now             func() time.Time
	Nonce           func() string
}

type aliRecord struct {
	RecordID string `json:"RecordId"`
	Value    string `json:"Value"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
}

type aliList struct {
	DomainRecords struct {
		Record []aliRecord `json:"Record"`
	} `json:"DomainRecords"`
}

type aliResp struct {
	RecordID string `json:"RecordId"`
}

type aliDomain struct {
	DomainName string `json:"DomainName"`
}

type aliDomainList struct {
	TotalCount int `json:"TotalCount"`
	PageNumber int `json:"PageNumber"`
	PageSize   int `json:"PageSize"`
	Domains    struct {
		Domain []aliDomain `json:"Domain"`
	} `json:"Domains"`
}

type aliEnvelope struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestID string `json:"RequestId"`
}

func (p *AliyunProvider) Name() string { return "aliyun" }

func (p *AliyunProvider) Capabilities() Capabilities {
	return Capabilities{
		CredentialsValidation: true,
		DDNS:                  true,
		DNS01:                 true,
		ZoneDiscovery:         true,
	}
}

func aliEscape(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

func (p *AliyunProvider) sign(params url.Values, now time.Time, nonce string) {
	params.Set("Format", "JSON")
	params.Set("Version", "2015-01-09")
	params.Set("AccessKeyId", p.AccessKeyID)
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", nonce)
	params.Set("Timestamp", now.UTC().Format("2006-01-02T15:04:05Z"))
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, aliEscape(k)+"="+aliEscape(v))
		}
	}
	canonical := strings.Join(parts, "&")
	stringToSign := "GET&%2F&" + aliEscape(canonical)
	mac := hmac.New(sha1.New, []byte(p.AccessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	params.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func randomNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func sanitizeAliyunMessage(kind ErrorKind, code, message string) string {
	// Aliyun authentication failures (notably SignatureDoesNotMatch) can echo
	// the canonical string-to-sign, including AccessKeyId, SignatureNonce and
	// other signed request material. Authentication diagnostics are therefore
	// intentionally code-driven and never preserve the remote message body.
	if kind == ErrorAuthentication {
		switch lc := strings.ToLower(strings.TrimSpace(code)); {
		case strings.Contains(lc, "signature"):
			return "Aliyun DNS API authentication failed: request signature was rejected"
		case strings.Contains(lc, "accesskey"):
			return "Aliyun DNS API authentication failed: AccessKey ID was rejected"
		case strings.Contains(lc, "securitytoken"):
			return "Aliyun DNS API authentication failed: security token was rejected"
		default:
			return "Aliyun DNS API authentication failed"
		}
	}

	msg := strings.TrimSpace(message)
	if msg == "" {
		return ""
	}
	lm := strings.ToLower(msg)
	for _, marker := range []string{
		"accesskeyid", "accesskeysecret", "access key id", "access key secret",
		"signature=", "signaturenonce", "signature nonce", "string to sign",
	} {
		if strings.Contains(lm, marker) {
			return "Aliyun DNS API rejected the request"
		}
	}
	return msg
}

func classifyAliyunCode(operation string, status int, code, message string) error {
	lc := strings.ToLower(strings.TrimSpace(code))
	kind := ErrorInvalidRequest
	retryable := false

	switch {
	case status == http.StatusTooManyRequests || strings.Contains(lc, "throttl") || strings.Contains(lc, "flowcontrol") || strings.Contains(lc, "ratelimit"):
		kind, retryable = ErrorRateLimit, true
	case status >= 500 || strings.Contains(lc, "serviceunavailable") || strings.Contains(lc, "internalerror") || strings.Contains(lc, "systemerror"):
		kind, retryable = ErrorTemporary, true
	case status == http.StatusUnauthorized || status == http.StatusForbidden ||
		strings.Contains(lc, "accesskey") || strings.Contains(lc, "signature") ||
		strings.Contains(lc, "securitytoken") || strings.Contains(lc, "forbidden") ||
		strings.Contains(lc, "permission") || strings.Contains(lc, "unauthor"):
		kind = ErrorAuthentication
	case strings.Contains(lc, "domainnotfound") || strings.Contains(lc, "invaliddomainname") || strings.Contains(lc, "invaliddomain"):
		kind = ErrorInvalidZone
	case strings.Contains(lc, "notfound") || strings.Contains(lc, "notbelongtouser"):
		kind = ErrorNotFound
	}

	message = sanitizeAliyunMessage(kind, code, message)
	if strings.TrimSpace(message) == "" {
		if code != "" {
			message = "Aliyun DNS API rejected the request"
		} else {
			message = fmt.Sprintf("Aliyun DNS API HTTP %d", status)
		}
	}
	return NewError("aliyun", operation, kind, code, message, retryable, nil)
}

func transportError(operation string, ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return NewError("aliyun", operation, ErrorContextCanceled, "", "request canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewError("aliyun", operation, ErrorTimeout, "", "request timed out", true, context.DeadlineExceeded)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return NewError("aliyun", operation, ErrorTimeout, "", "request timed out", true, err)
	}
	// net/http's url.Error includes the full signed URL. Never preserve it as
	// Cause or text because it contains AccessKeyId, Signature and nonce.
	if ue, ok := err.(*url.Error); ok {
		return NewError("aliyun", operation, ErrorNetworkUnavailable, "", fmt.Sprint(ue.Err), true, nil)
	}
	return NewError("aliyun", operation, ErrorNetworkUnavailable, "", err.Error(), true, nil)
}

func (p *AliyunProvider) call(ctx context.Context, operation string, params url.Values, out any) error {
	if strings.TrimSpace(p.AccessKeyID) == "" || strings.TrimSpace(p.AccessKeySecret) == "" {
		return NewError("aliyun", operation, ErrorAuthentication, "credentials_missing", "AccessKey ID or Secret is not configured", false, nil)
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	nonce := p.Nonce
	if nonce == nil {
		nonce = randomNonce
	}
	p.sign(params, now(), nonce())

	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = aliyunEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return NewError("aliyun", operation, ErrorInvalidRequest, "invalid_endpoint", "invalid provider endpoint", false, nil)
	}
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return NewError("aliyun", operation, ErrorInvalidRequest, "invalid_request", "unable to build provider request", false, err)
	}

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: aliyunRequestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return transportError(operation, ctx, err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return NewError("aliyun", operation, ErrorTemporary, "response_read_failed", "unable to read provider response", true, readErr)
	}

	var envelope aliEnvelope
	_ = json.Unmarshal(data, &envelope)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || envelope.Code != "" {
		return classifyAliyunCode(operation, resp.StatusCode, envelope.Code, envelope.Message)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return NewError("aliyun", operation, ErrorTemporary, "invalid_response", "unable to decode provider response", true, err)
		}
	}
	return nil
}

func (p *AliyunProvider) find(ctx context.Context, zone, host, typ string) ([]aliRecord, error) {
	q := url.Values{
		"Action":     {"DescribeSubDomainRecords"},
		"DomainName": {zone},
		"SubDomain":  {FullDomain(zone, host)},
		"Type":       {typ},
	}
	var out aliList
	if err := p.call(ctx, "records.list", q, &out); err != nil {
		return nil, err
	}
	return out.DomainRecords.Record, nil
}

func (p *AliyunProvider) Upsert(ctx context.Context, zone, host, typ, value string, ttl int) (string, error) {
	records, err := p.find(ctx, zone, host, typ)
	if err != nil {
		return "", err
	}
	rr := host
	if rr == "" {
		rr = "@"
	}
	if strings.HasSuffix(rr, "."+zone) {
		rr = strings.TrimSuffix(rr, "."+zone)
	}
	for _, record := range records {
		if record.Value == value {
			return "unchanged", nil
		}
	}
	if len(records) > 0 && !strings.EqualFold(typ, "TXT") {
		q := url.Values{
			"Action":   {"UpdateDomainRecord"},
			"RecordId": {records[0].RecordID},
			"RR":       {rr}, "Type": {typ}, "Value": {value}, "TTL": {fmt.Sprint(ttl)},
		}
		var out aliResp
		if err := p.call(ctx, "records.update", q, &out); err != nil {
			return "", err
		}
		return "updated", nil
	}
	q := url.Values{
		"Action": {"AddDomainRecord"}, "DomainName": {zone}, "RR": {rr},
		"Type": {typ}, "Value": {value}, "TTL": {fmt.Sprint(ttl)},
	}
	var out aliResp
	if err := p.call(ctx, "records.create", q, &out); err != nil {
		return "", err
	}
	return "created", nil
}

func (p *AliyunProvider) Delete(ctx context.Context, zone, host, typ, value string) error {
	records, err := p.find(ctx, zone, host, typ)
	if err != nil {
		return err
	}
	for _, record := range records {
		if value != "" && record.Value != value {
			continue
		}
		q := url.Values{"Action": {"DeleteDomainRecord"}, "RecordId": {record.RecordID}}
		var out aliResp
		if err := p.call(ctx, "records.delete", q, &out); err != nil {
			return err
		}
	}
	return nil
}

func (p *AliyunProvider) listDomainsPage(ctx context.Context, page, pageSize int) (aliDomainList, error) {
	q := url.Values{
		"Action":     {"DescribeDomains"},
		"PageNumber": {fmt.Sprint(page)},
		"PageSize":   {fmt.Sprint(pageSize)},
	}
	var out aliDomainList
	if err := p.call(ctx, "zones.list", q, &out); err != nil {
		return aliDomainList{}, err
	}
	return out, nil
}

// ValidateCredentials performs the smallest read-only API request needed to
// verify that the saved account can authenticate to Aliyun DNS.
func (p *AliyunProvider) ValidateCredentials(ctx context.Context) error {
	_, err := p.listDomainsPage(ctx, 1, 1)
	return err
}

// ListZones returns the root DNS zones managed by this Aliyun DNS account.
// DescribeDomains is paginated; keep following pages until TotalCount is
// satisfied while normalizing names for deterministic UI presentation.
func (p *AliyunProvider) ListZones(ctx context.Context) ([]string, error) {
	zones := make([]string, 0)
	seen := map[string]bool{}
	fetched := 0
	const pageSize = 100
	for page := 1; page <= 1000; page++ {
		out, err := p.listDomainsPage(ctx, page, pageSize)
		if err != nil {
			return nil, err
		}
		fetched += len(out.Domains.Domain)
		for _, d := range out.Domains.Domain {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.DomainName), "."))
			if name != "" && !seen[name] {
				seen[name] = true
				zones = append(zones, name)
			}
		}
		if out.TotalCount <= fetched || len(out.Domains.Domain) == 0 {
			break
		}
	}
	sort.Strings(zones)
	return zones, nil
}
