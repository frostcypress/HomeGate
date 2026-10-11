package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const huaweiRequestTimeout = 20 * time.Second

type HuaweiCloudProvider struct {
	AccessKey string
	SecretKey string
	AccountID string
	Endpoint  string
	Client    *http.Client
	Now       func() time.Time
}

type huaweiZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type huaweiZoneList struct {
	Zones []huaweiZone `json:"zones"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Metadata struct {
		TotalCount int `json:"total_count"`
	} `json:"metadata"`
}

type huaweiRecordSet struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

type huaweiRecordSetList struct {
	RecordSets []huaweiRecordSet `json:"recordsets"`
	Links      struct {
		Next string `json:"next"`
	} `json:"links"`
	Metadata struct {
		TotalCount int `json:"total_count"`
	} `json:"metadata"`
}

func (p *HuaweiCloudProvider) Name() string { return "huaweicloud" }
func (p *HuaweiCloudProvider) Capabilities() Capabilities {
	return Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true}
}

func huaweiPercentEncode(s string) string {
	// Huawei's signature algorithm follows RFC 3986 query encoding: spaces are
	// %20 (not '+') and parameters are sorted after URI encoding.
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

func huaweiCanonicalQuery(q url.Values) string {
	type pair struct{ k, v string }
	pairs := make([]pair, 0)
	for k, values := range q {
		if len(values) == 0 {
			values = []string{""}
		}
		for _, v := range values {
			pairs = append(pairs, pair{huaweiPercentEncode(k), huaweiPercentEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.k+"="+p.v)
	}
	return strings.Join(out, "&")
}

func huaweiCanonicalURI(path string) string {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Huawei canonical URI normalization uses a trailing slash even when the
	// actual resource request URI does not contain one.
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func huaweiSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func huaweiHMACSHA256(key []byte, data string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func (p *HuaweiCloudProvider) sign(req *http.Request, body []byte, now time.Time) {
	const algorithm = "SDK-HMAC-SHA256"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sdk-Date", now.UTC().Format("20060102T150405Z"))
	req.Header.Set("X-Domain-ID", strings.TrimSpace(p.AccountID))

	headers := map[string]string{
		"content-type": strings.TrimSpace(req.Header.Get("Content-Type")),
		"host":         strings.TrimSpace(req.URL.Host),
		"x-domain-id":  strings.TrimSpace(req.Header.Get("X-Domain-ID")),
		"x-sdk-date":   strings.TrimSpace(req.Header.Get("X-Sdk-Date")),
	}
	signedNames := []string{"content-type", "host", "x-domain-id", "x-sdk-date"}
	var canonicalHeaders strings.Builder
	for _, name := range signedNames {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(headers[name]), " "))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signedNames, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		huaweiCanonicalURI(req.URL.EscapedPath()),
		huaweiCanonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		huaweiSHA256Hex(body),
	}, "\n")
	stringToSign := algorithm + "\n" + req.Header.Get("X-Sdk-Date") + "\n" + huaweiSHA256Hex([]byte(canonicalRequest))
	signature := huaweiHMACSHA256([]byte(p.SecretKey), stringToSign)
	req.Header.Set("Authorization", algorithm+" Access="+p.AccessKey+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func huaweiClassify(operation, code string, status int) error {
	lc := strings.ToLower(strings.TrimSpace(code))
	kind, retryable := ErrorInvalidRequest, false
	switch {
	case status == http.StatusTooManyRequests || strings.Contains(lc, "throttl") || strings.Contains(lc, "ratelimit") || strings.Contains(lc, "too_many_requests"):
		kind, retryable = ErrorRateLimit, true
	case status >= 500 || strings.Contains(lc, "internal") || strings.Contains(lc, "unavailable"):
		kind, retryable = ErrorTemporary, true
	case status == http.StatusUnauthorized || status == http.StatusForbidden || strings.Contains(lc, "auth") || strings.Contains(lc, "forbidden") || strings.Contains(lc, "permission") || strings.Contains(lc, "access"):
		kind = ErrorAuthentication
	case status == http.StatusNotFound || strings.Contains(lc, "not_found") || strings.Contains(lc, "notfound"):
		kind = ErrorNotFound
	case strings.Contains(lc, "zone") && (strings.Contains(lc, "invalid") || strings.Contains(lc, "not")):
		kind = ErrorInvalidZone
	}
	message := "Huawei Cloud DNS API rejected the request"
	if kind == ErrorAuthentication {
		message = "Huawei Cloud DNS credentials were rejected or lack required permissions"
	} else if kind == ErrorRateLimit {
		message = "Huawei Cloud DNS API rate limit reached"
	} else if kind == ErrorTemporary {
		message = "Huawei Cloud DNS API is temporarily unavailable"
	}
	return NewError("huaweicloud", operation, kind, code, message, retryable, nil)
}

func huaweiTransportError(operation string, ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return NewError("huaweicloud", operation, ErrorContextCanceled, "", "request canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewError("huaweicloud", operation, ErrorTimeout, "", "request timed out", true, context.DeadlineExceeded)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return NewError("huaweicloud", operation, ErrorTimeout, "", "request timed out", true, nil)
	}
	if ue, ok := err.(*url.Error); ok {
		return NewError("huaweicloud", operation, ErrorNetworkUnavailable, "", fmt.Sprint(ue.Err), true, nil)
	}
	return NewError("huaweicloud", operation, ErrorNetworkUnavailable, "", "network request failed", true, nil)
}

func (p *HuaweiCloudProvider) request(ctx context.Context, operation, method, path string, query url.Values, payload any, out any) error {
	if strings.TrimSpace(p.AccessKey) == "" || strings.TrimSpace(p.SecretKey) == "" || strings.TrimSpace(p.AccountID) == "" {
		return NewError("huaweicloud", operation, ErrorAuthentication, "credentials_missing", "Access Key ID, Secret Access Key or Account ID is not configured", false, nil)
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		return NewError("huaweicloud", operation, ErrorInvalidRequest, "endpoint_missing", "Huawei Cloud DNS API endpoint is not configured", false, nil)
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return NewError("huaweicloud", operation, ErrorInvalidRequest, "invalid_endpoint", "invalid Huawei Cloud DNS API endpoint", false, nil)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(path, "/")
	base.RawQuery = query.Encode()

	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return NewError("huaweicloud", operation, ErrorInvalidRequest, "invalid_request", "unable to encode provider request", false, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return NewError("huaweicloud", operation, ErrorInvalidRequest, "invalid_request", "unable to build provider request", false, err)
	}
	nowFn := p.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	p.sign(req, body, nowFn().UTC())

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: huaweiRequestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return huaweiTransportError(operation, ctx, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return NewError("huaweicloud", operation, ErrorTemporary, "response_read_failed", "unable to read provider response", true, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			ErrorCode string `json:"error_code"`
			ErrorMsg  string `json:"error_msg"`
		}
		_ = json.Unmarshal(data, &apiErr)
		code := apiErr.Code
		if code == "" {
			code = apiErr.ErrorCode
		}
		return huaweiClassify(operation, code, resp.StatusCode)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return NewError("huaweicloud", operation, ErrorTemporary, "invalid_response", "unable to decode provider response", true, err)
		}
	}
	return nil
}

func huaweiFQDN(zone, host string) string {
	return strings.TrimSuffix(FullDomain(zone, host), ".") + "."
}

func huaweiAPIRecordValue(typ, value string) string {
	if strings.EqualFold(strings.TrimSpace(typ), "TXT") {
		return strconv.Quote(value)
	}
	return value
}

func huaweiLogicalRecordValue(typ, value string) string {
	if !strings.EqualFold(strings.TrimSpace(typ), "TXT") {
		return value
	}
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

func (p *HuaweiCloudProvider) listZonesPage(ctx context.Context, marker string) (huaweiZoneList, error) {
	q := url.Values{"type": {"public"}, "limit": {"500"}}
	if marker != "" {
		q.Set("marker", marker)
	}
	var out huaweiZoneList
	err := p.request(ctx, "zones.list", http.MethodGet, "/v2/zones", q, nil, &out)
	return out, err
}

func (p *HuaweiCloudProvider) ListZones(ctx context.Context) ([]string, error) {
	zones := make([]string, 0)
	seen := make(map[string]bool)
	marker := ""
	for pages := 0; pages < 1000; pages++ {
		out, err := p.listZonesPage(ctx, marker)
		if err != nil {
			return nil, err
		}
		for _, z := range out.Zones {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
			if name != "" && !seen[name] {
				seen[name] = true
				zones = append(zones, name)
			}
		}
		if len(out.Zones) < 500 {
			break
		}
		next := strings.TrimSpace(out.Zones[len(out.Zones)-1].ID)
		if next == "" || next == marker {
			break
		}
		marker = next
	}
	sort.Strings(zones)
	return zones, nil
}

func (p *HuaweiCloudProvider) ValidateCredentials(ctx context.Context) error {
	q := url.Values{"type": {"public"}, "limit": {"1"}}
	var out huaweiZoneList
	return p.request(ctx, "credentials.validate", http.MethodGet, "/v2/zones", q, nil, &out)
}

func (p *HuaweiCloudProvider) zoneID(ctx context.Context, zone string) (string, error) {
	target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	marker := ""
	for pages := 0; pages < 1000; pages++ {
		q := url.Values{"type": {"public"}, "name": {target}, "search_mode": {"equal"}, "limit": {"500"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		var out huaweiZoneList
		if err := p.request(ctx, "zones.resolve", http.MethodGet, "/v2/zones", q, nil, &out); err != nil {
			return "", err
		}
		for _, z := range out.Zones {
			if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".") == target {
				return z.ID, nil
			}
		}
		if len(out.Zones) < 500 {
			break
		}
		next := strings.TrimSpace(out.Zones[len(out.Zones)-1].ID)
		if next == "" || next == marker {
			break
		}
		marker = next
	}
	return "", NewError("huaweicloud", "zones.resolve", ErrorInvalidZone, "zone_not_found", "Huawei Cloud DNS zone was not found", false, nil)
}

func (p *HuaweiCloudProvider) listRecordSets(ctx context.Context, zoneID, fqdn, typ string) ([]huaweiRecordSet, error) {
	records := make([]huaweiRecordSet, 0)
	marker := ""
	for pages := 0; pages < 1000; pages++ {
		q := url.Values{"limit": {"500"}, "name": {fqdn}, "type": {strings.ToUpper(strings.TrimSpace(typ))}, "search_mode": {"equal"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		var out huaweiRecordSetList
		path := "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets"
		if err := p.request(ctx, "records.list", http.MethodGet, path, q, nil, &out); err != nil {
			return nil, err
		}
		for _, r := range out.RecordSets {
			if strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(fqdn, ".")) && strings.EqualFold(r.Type, typ) {
				records = append(records, r)
			}
		}
		if len(out.RecordSets) < 500 {
			break
		}
		next := strings.TrimSpace(out.RecordSets[len(out.RecordSets)-1].ID)
		if next == "" || next == marker {
			break
		}
		marker = next
	}
	return records, nil
}

func (p *HuaweiCloudProvider) updateRecordSet(ctx context.Context, zoneID string, r huaweiRecordSet, values []string, ttl int) error {
	if ttl <= 0 {
		ttl = r.TTL
	}
	if ttl <= 0 {
		ttl = 300
	}
	payload := map[string]any{"name": r.Name, "type": strings.ToUpper(r.Type), "ttl": ttl, "records": values}
	path := "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(r.ID)
	return p.request(ctx, "records.update", http.MethodPut, path, nil, payload, nil)
}

func (p *HuaweiCloudProvider) createRecordSet(ctx context.Context, zoneID, fqdn, typ, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 300
	}
	payload := map[string]any{"name": fqdn, "type": strings.ToUpper(strings.TrimSpace(typ)), "ttl": ttl, "records": []string{huaweiAPIRecordValue(typ, value)}}
	path := "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets"
	return p.request(ctx, "records.create", http.MethodPost, path, nil, payload, nil)
}

func (p *HuaweiCloudProvider) deleteRecordSet(ctx context.Context, zoneID, recordID string) error {
	path := "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(recordID)
	return p.request(ctx, "records.delete", http.MethodDelete, path, nil, nil, nil)
}

func (p *HuaweiCloudProvider) Upsert(ctx context.Context, zone, host, typ, value string, ttl int) (string, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return "", err
	}
	fqdn := huaweiFQDN(zone, host)
	recordsets, err := p.listRecordSets(ctx, zoneID, fqdn, typ)
	if err != nil {
		return "", err
	}
	for _, r := range recordsets {
		for _, current := range r.Records {
			if huaweiLogicalRecordValue(typ, current) == value {
				return "unchanged", nil
			}
		}
	}
	if len(recordsets) == 0 {
		if err := p.createRecordSet(ctx, zoneID, fqdn, typ, value, ttl); err != nil {
			return "", err
		}
		return "created", nil
	}

	// Huawei groups same-name/type values inside one record set. For TXT DNS-01
	// append only the HomeGate value so unrelated validation TXT remains intact.
	r := recordsets[0]
	if strings.EqualFold(typ, "TXT") {
		values := append([]string(nil), r.Records...)
		values = append(values, huaweiAPIRecordValue(typ, value))
		if err := p.updateRecordSet(ctx, zoneID, r, values, ttl); err != nil {
			return "", err
		}
		return "created", nil
	}
	if err := p.updateRecordSet(ctx, zoneID, r, []string{value}, ttl); err != nil {
		return "", err
	}
	return "updated", nil
}

func (p *HuaweiCloudProvider) Delete(ctx context.Context, zone, host, typ, value string) error {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	fqdn := huaweiFQDN(zone, host)
	recordsets, err := p.listRecordSets(ctx, zoneID, fqdn, typ)
	if err != nil {
		return err
	}
	for _, r := range recordsets {
		if value == "" {
			if err := p.deleteRecordSet(ctx, zoneID, r.ID); err != nil {
				return err
			}
			continue
		}
		kept := make([]string, 0, len(r.Records))
		removed := false
		for _, current := range r.Records {
			if huaweiLogicalRecordValue(typ, current) == value {
				removed = true
				continue
			}
			kept = append(kept, current)
		}
		if !removed {
			continue
		}
		if len(kept) == 0 {
			if err := p.deleteRecordSet(ctx, zoneID, r.ID); err != nil {
				return err
			}
		} else if err := p.updateRecordSet(ctx, zoneID, r, kept, r.TTL); err != nil {
			return err
		}
	}
	return nil
}
