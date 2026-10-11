package dnsprovider

import (
	"bytes"
	"context"
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

const (
	cloudflareEndpoint       = "https://api.cloudflare.com/client/v4"
	cloudflareRequestTimeout = 20 * time.Second
)

type CloudflareProvider struct {
	Token    string
	Client   HTTPDoer
	Endpoint string
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	TotalCount int `json:"total_count"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cfZonesEnvelope struct {
	Success    bool         `json:"success"`
	Errors     []cfMessage  `json:"errors"`
	Result     []cfZone     `json:"result"`
	ResultInfo cfResultInfo `json:"result_info"`
}

type cfRecordsEnvelope struct {
	Success    bool         `json:"success"`
	Errors     []cfMessage  `json:"errors"`
	Result     []cfRecord   `json:"result"`
	ResultInfo cfResultInfo `json:"result_info"`
}

type cfRecordEnvelope struct {
	Success bool        `json:"success"`
	Errors  []cfMessage `json:"errors"`
	Result  cfRecord    `json:"result"`
}

type cfDeleteEnvelope struct {
	Success bool        `json:"success"`
	Errors  []cfMessage `json:"errors"`
	Result  struct {
		ID string `json:"id"`
	} `json:"result"`
}

func (p *CloudflareProvider) Name() string { return "cloudflare" }

func (p *CloudflareProvider) Capabilities() Capabilities {
	return Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true}
}

func cloudflareError(operation string, status int, errorsList []cfMessage) error {
	code := ""
	if len(errorsList) > 0 && errorsList[0].Code != 0 {
		code = strconv.Itoa(errorsList[0].Code)
	}
	kind, retryable := ErrorInvalidRequest, false
	switch {
	case status == http.StatusTooManyRequests:
		kind, retryable = ErrorRateLimit, true
	case status >= 500:
		kind, retryable = ErrorTemporary, true
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		kind = ErrorAuthentication
	case status == http.StatusNotFound:
		kind = ErrorNotFound
	}
	if len(errorsList) > 0 {
		lc := strings.ToLower(errorsList[0].Message)
		switch {
		case strings.Contains(lc, "rate limit"):
			kind, retryable = ErrorRateLimit, true
		case strings.Contains(lc, "authentication") || strings.Contains(lc, "permission") || strings.Contains(lc, "authorization"):
			kind = ErrorAuthentication
		case strings.Contains(lc, "zone") && strings.Contains(lc, "not found"):
			kind = ErrorInvalidZone
		}
	}
	message := "Cloudflare DNS API rejected the request"
	if kind == ErrorAuthentication {
		message = "Cloudflare API token was rejected or lacks required DNS permissions"
	} else if kind == ErrorRateLimit {
		message = "Cloudflare DNS API rate limit reached"
	} else if kind == ErrorTemporary {
		message = "Cloudflare DNS API is temporarily unavailable"
	}
	return NewError("cloudflare", operation, kind, code, message, retryable, nil)
}

func cloudflareTransportError(operation string, ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return NewError("cloudflare", operation, ErrorContextCanceled, "", "request canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewError("cloudflare", operation, ErrorTimeout, "", "request timed out", true, context.DeadlineExceeded)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return NewError("cloudflare", operation, ErrorTimeout, "", "request timed out", true, nil)
	}
	if ue, ok := err.(*url.Error); ok {
		return NewError("cloudflare", operation, ErrorNetworkUnavailable, "", fmt.Sprint(ue.Err), true, nil)
	}
	return NewError("cloudflare", operation, ErrorNetworkUnavailable, "", "network request failed", true, nil)
}

func (p *CloudflareProvider) call(ctx context.Context, operation, method, path string, query url.Values, body any, out any) error {
	if strings.TrimSpace(p.Token) == "" {
		return NewError("cloudflare", operation, ErrorAuthentication, "credentials_missing", "API Token is not configured", false, nil)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(p.Endpoint), "/")
	if endpoint == "" {
		endpoint = cloudflareEndpoint
	}
	u, err := url.Parse(endpoint + path)
	if err != nil {
		return NewError("cloudflare", operation, ErrorInvalidRequest, "invalid_endpoint", "invalid provider endpoint", false, nil)
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return NewError("cloudflare", operation, ErrorInvalidRequest, "invalid_request", "unable to encode provider request", false, err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return NewError("cloudflare", operation, ErrorInvalidRequest, "invalid_request", "unable to build provider request", false, err)
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: cloudflareRequestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return cloudflareTransportError(operation, ctx, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return NewError("cloudflare", operation, ErrorTemporary, "response_read_failed", "unable to read provider response", true, err)
	}
	var base struct {
		Success bool        `json:"success"`
		Errors  []cfMessage `json:"errors"`
	}
	_ = json.Unmarshal(data, &base)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !base.Success {
		return cloudflareError(operation, resp.StatusCode, base.Errors)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return NewError("cloudflare", operation, ErrorTemporary, "invalid_response", "unable to decode provider response", true, err)
		}
	}
	return nil
}

func (p *CloudflareProvider) listZonesPage(ctx context.Context, name string, page, perPage int) (cfZonesEnvelope, error) {
	q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}
	if strings.TrimSpace(name) != "" {
		q.Set("name", strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."))
	}
	var out cfZonesEnvelope
	if err := p.call(ctx, "zones.list", http.MethodGet, "/zones", q, nil, &out); err != nil {
		return cfZonesEnvelope{}, err
	}
	return out, nil
}

func (p *CloudflareProvider) zoneID(ctx context.Context, zone string) (string, error) {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	out, err := p.listZonesPage(ctx, zone, 1, 50)
	if err != nil {
		return "", err
	}
	for _, z := range out.Result {
		if strings.EqualFold(strings.TrimSuffix(z.Name, "."), zone) {
			return z.ID, nil
		}
	}
	return "", NewError("cloudflare", "zones.resolve", ErrorInvalidZone, "zone_not_found", "DNS zone is not available to this Cloudflare account", false, nil)
}

func (p *CloudflareProvider) listRecords(ctx context.Context, zoneID, fqdn, typ string) ([]cfRecord, error) {
	q := url.Values{"type": {strings.ToUpper(strings.TrimSpace(typ))}, "name": {strings.TrimSuffix(strings.TrimSpace(fqdn), ".")}, "per_page": {"100"}}
	var out cfRecordsEnvelope
	if err := p.call(ctx, "records.list", http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (p *CloudflareProvider) Upsert(ctx context.Context, zone, host, typ, value string, ttl int) (string, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return "", err
	}
	fqdn := FullDomain(zone, host)
	records, err := p.listRecords(ctx, zoneID, fqdn, typ)
	if err != nil {
		return "", err
	}
	for _, r := range records {
		if r.Content == value {
			return "unchanged", nil
		}
	}
	payload := map[string]any{"type": strings.ToUpper(typ), "name": fqdn, "content": value, "ttl": ttl}
	if len(records) > 0 && !strings.EqualFold(typ, "TXT") {
		var out cfRecordEnvelope
		if err := p.call(ctx, "records.update", http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(records[0].ID), nil, payload, &out); err != nil {
			return "", err
		}
		return "updated", nil
	}
	var out cfRecordEnvelope
	if err := p.call(ctx, "records.create", http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, payload, &out); err != nil {
		return "", err
	}
	return "created", nil
}

func (p *CloudflareProvider) Delete(ctx context.Context, zone, host, typ, value string) error {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	records, err := p.listRecords(ctx, zoneID, FullDomain(zone, host), typ)
	if err != nil {
		return err
	}
	for _, r := range records {
		if value != "" && r.Content != value {
			continue
		}
		var out cfDeleteEnvelope
		if err := p.call(ctx, "records.delete", http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(r.ID), nil, nil, &out); err != nil {
			return err
		}
	}
	return nil
}

func (p *CloudflareProvider) ValidateCredentials(ctx context.Context) error {
	_, err := p.listZonesPage(ctx, "", 1, 1)
	return err
}

func (p *CloudflareProvider) ListZones(ctx context.Context) ([]string, error) {
	zones := make([]string, 0)
	seen := map[string]bool{}
	for page := 1; page <= 1000; page++ {
		out, err := p.listZonesPage(ctx, "", page, 50)
		if err != nil {
			return nil, err
		}
		for _, z := range out.Result {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
			if name != "" && !seen[name] {
				seen[name] = true
				zones = append(zones, name)
			}
		}
		if len(out.Result) == 0 || out.ResultInfo.TotalPages == 0 || page >= out.ResultInfo.TotalPages {
			break
		}
	}
	sort.Strings(zones)
	return zones, nil
}
