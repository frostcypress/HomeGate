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
	"strings"
	"time"
)

const (
	dnspodEndpoint       = "https://dnspod.tencentcloudapi.com"
	dnspodAPIVersion     = "2021-03-23"
	dnspodRequestTimeout = 20 * time.Second
)

type DNSPodProvider struct {
	SecretID  string
	SecretKey string
	Client    HTTPDoer
	Endpoint  string
	Now       func() time.Time
}

type dnspodAPIError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type dnspodRecord struct {
	RecordID uint64 `json:"RecordId"`
	Name     string `json:"Name"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	Line     string `json:"Line"`
	TTL      uint64 `json:"TTL"`
}

type dnspodRecordListResponse struct {
	Response struct {
		RecordList []dnspodRecord  `json:"RecordList"`
		Error      *dnspodAPIError `json:"Error,omitempty"`
		RequestID  string          `json:"RequestId"`
	} `json:"Response"`
}

type dnspodDomain struct {
	Name string `json:"Name"`
}

type dnspodDomainListResponse struct {
	Response struct {
		DomainList []dnspodDomain  `json:"DomainList"`
		Error      *dnspodAPIError `json:"Error,omitempty"`
		RequestID  string          `json:"RequestId"`
	} `json:"Response"`
}

type dnspodMutationResponse struct {
	Response struct {
		RecordID  uint64          `json:"RecordId"`
		Error     *dnspodAPIError `json:"Error,omitempty"`
		RequestID string          `json:"RequestId"`
	} `json:"Response"`
}

func (p *DNSPodProvider) Name() string { return "dnspod" }
func (p *DNSPodProvider) Capabilities() Capabilities {
	return Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true}
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (p *DNSPodProvider) authorization(host string, payload []byte, now time.Time) string {
	const algorithm = "TC3-HMAC-SHA256"
	contentType := "application/json; charset=utf-8"
	canonicalHeaders := "content-type:" + contentType + "\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + sha256Hex(payload)
	date := now.UTC().Format("2006-01-02")
	credentialScope := date + "/dnspod/tc3_request"
	stringToSign := algorithm + "\n" + fmt.Sprint(now.Unix()) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))
	secretDate := hmacSHA256([]byte("TC3"+p.SecretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte("dnspod"))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))
	return algorithm + " Credential=" + p.SecretID + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func dnspodClassify(operation, code string, status int) error {
	lc := strings.ToLower(strings.TrimSpace(code))
	kind, retryable := ErrorInvalidRequest, false
	switch {
	case status == http.StatusTooManyRequests || strings.Contains(lc, "requestlimit") || strings.Contains(lc, "frequencylimit") || strings.Contains(lc, "limitexceeded"):
		kind, retryable = ErrorRateLimit, true
	case status >= 500 || strings.HasPrefix(lc, "internalerror") || strings.Contains(lc, "unknowerror") || strings.Contains(lc, "operatefailed"):
		kind, retryable = ErrorTemporary, true
	case status == http.StatusUnauthorized || status == http.StatusForbidden || strings.HasPrefix(lc, "authfailure") || strings.HasPrefix(lc, "unauthorizedoperation") || strings.Contains(lc, "loginfailed") || strings.Contains(lc, "nopermission") || strings.Contains(lc, "accessdenied"):
		kind = ErrorAuthentication
	case strings.Contains(lc, "domainnotexists") || strings.Contains(lc, "domaininvalid") || strings.Contains(lc, "domainidinvalid"):
		kind = ErrorInvalidZone
	case strings.Contains(lc, "recordidinvalid") || strings.Contains(lc, "notexists"):
		kind = ErrorNotFound
	}
	message := "Tencent DNSPod API rejected the request"
	if kind == ErrorAuthentication {
		message = "Tencent DNSPod credentials were rejected or lack required permissions"
	} else if kind == ErrorRateLimit {
		message = "Tencent DNSPod API rate limit reached"
	} else if kind == ErrorTemporary {
		message = "Tencent DNSPod API is temporarily unavailable"
	}
	return NewError("dnspod", operation, kind, code, message, retryable, nil)
}

func dnspodTransportError(operation string, ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return NewError("dnspod", operation, ErrorContextCanceled, "", "request canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return NewError("dnspod", operation, ErrorTimeout, "", "request timed out", true, context.DeadlineExceeded)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return NewError("dnspod", operation, ErrorTimeout, "", "request timed out", true, nil)
	}
	if ue, ok := err.(*url.Error); ok {
		return NewError("dnspod", operation, ErrorNetworkUnavailable, "", fmt.Sprint(ue.Err), true, nil)
	}
	return NewError("dnspod", operation, ErrorNetworkUnavailable, "", "network request failed", true, nil)
}

func (p *DNSPodProvider) call(ctx context.Context, operation, action string, payload any, out any) error {
	if strings.TrimSpace(p.SecretID) == "" || strings.TrimSpace(p.SecretKey) == "" {
		return NewError("dnspod", operation, ErrorAuthentication, "credentials_missing", "SecretId or SecretKey is not configured", false, nil)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return NewError("dnspod", operation, ErrorInvalidRequest, "invalid_request", "unable to encode provider request", false, err)
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = dnspodEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return NewError("dnspod", operation, ErrorInvalidRequest, "invalid_endpoint", "invalid provider endpoint", false, nil)
	}
	nowFn := p.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return NewError("dnspod", operation, ErrorInvalidRequest, "invalid_request", "unable to build provider request", false, err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", u.Host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", dnspodAPIVersion)
	req.Header.Set("X-TC-Timestamp", fmt.Sprint(now.Unix()))
	req.Header.Set("Authorization", p.authorization(u.Host, body, now))
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: dnspodRequestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return dnspodTransportError(operation, ctx, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return NewError("dnspod", operation, ErrorTemporary, "response_read_failed", "unable to read provider response", true, err)
	}
	var base struct {
		Response struct {
			Error *dnspodAPIError `json:"Error,omitempty"`
		} `json:"Response"`
	}
	_ = json.Unmarshal(data, &base)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || base.Response.Error != nil {
		code := ""
		if base.Response.Error != nil {
			code = base.Response.Error.Code
		}
		return dnspodClassify(operation, code, resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return NewError("dnspod", operation, ErrorTemporary, "invalid_response", "unable to decode provider response", true, err)
		}
	}
	return nil
}

func dnspodSubDomain(zone, host string) string {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || host == "@" || host == zone {
		return "@"
	}
	if strings.HasSuffix(host, "."+zone) {
		host = strings.TrimSuffix(host, "."+zone)
	}
	return host
}

func (p *DNSPodProvider) listRecords(ctx context.Context, zone, host, typ string) ([]dnspodRecord, error) {
	payload := map[string]any{"Domain": strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), "."), "Subdomain": dnspodSubDomain(zone, host), "RecordType": strings.ToUpper(strings.TrimSpace(typ)), "Limit": 3000, "Offset": 0}
	var out dnspodRecordListResponse
	if err := p.call(ctx, "records.list", "DescribeRecordList", payload, &out); err != nil {
		return nil, err
	}
	return out.Response.RecordList, nil
}

func (p *DNSPodProvider) Upsert(ctx context.Context, zone, host, typ, value string, ttl int) (string, error) {
	records, err := p.listRecords(ctx, zone, host, typ)
	if err != nil {
		return "", err
	}
	for _, r := range records {
		if r.Value == value {
			return "unchanged", nil
		}
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	sub := dnspodSubDomain(zone, host)
	if len(records) > 0 && !strings.EqualFold(typ, "TXT") {
		payload := map[string]any{"Domain": zone, "RecordType": strings.ToUpper(typ), "RecordLine": "默认", "Value": value, "RecordId": records[0].RecordID, "SubDomain": sub, "TTL": ttl}
		var out dnspodMutationResponse
		if err := p.call(ctx, "records.update", "ModifyRecord", payload, &out); err != nil {
			return "", err
		}
		return "updated", nil
	}
	payload := map[string]any{"Domain": zone, "RecordType": strings.ToUpper(typ), "RecordLine": "默认", "Value": value, "SubDomain": sub, "TTL": ttl}
	var out dnspodMutationResponse
	if err := p.call(ctx, "records.create", "CreateRecord", payload, &out); err != nil {
		return "", err
	}
	return "created", nil
}

func (p *DNSPodProvider) Delete(ctx context.Context, zone, host, typ, value string) error {
	records, err := p.listRecords(ctx, zone, host, typ)
	if err != nil {
		return err
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	for _, r := range records {
		if value != "" && r.Value != value {
			continue
		}
		payload := map[string]any{"Domain": zone, "RecordId": r.RecordID}
		var out dnspodMutationResponse
		if err := p.call(ctx, "records.delete", "DeleteRecord", payload, &out); err != nil {
			return err
		}
	}
	return nil
}

func (p *DNSPodProvider) ValidateCredentials(ctx context.Context) error {
	var out dnspodDomainListResponse
	return p.call(ctx, "credentials.validate", "DescribeDomainList", map[string]any{"Type": "ALL", "Offset": 0, "Limit": 1}, &out)
}

func (p *DNSPodProvider) ListZones(ctx context.Context) ([]string, error) {
	zones := make([]string, 0)
	seen := map[string]bool{}
	const limit = 100
	for offset := 0; offset < 100000; offset += limit {
		var out dnspodDomainListResponse
		if err := p.call(ctx, "zones.list", "DescribeDomainList", map[string]any{"Type": "ALL", "Offset": offset, "Limit": limit}, &out); err != nil {
			return nil, err
		}
		for _, d := range out.Response.DomainList {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Name)), ".")
			if name != "" && !seen[name] {
				seen[name] = true
				zones = append(zones, name)
			}
		}
		if len(out.Response.DomainList) < limit {
			break
		}
	}
	sort.Strings(zones)
	return zones, nil
}
