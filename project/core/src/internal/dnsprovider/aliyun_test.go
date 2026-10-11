package dnsprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fixedAliyunProvider(endpoint string) *AliyunProvider {
	return &AliyunProvider{
		AccessKeyID: "id", AccessKeySecret: "secret", Endpoint: endpoint,
		Now:   func() time.Time { return time.Date(2026, 9, 5, 5, 0, 0, 0, time.UTC) },
		Nonce: func() string { return "nonce" },
	}
}

func TestAliyunUnchanged(t *testing.T) {
	var queries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query())
		io.WriteString(w, `{"DomainRecords":{"Record":[{"RecordId":"r1","Value":"2001:db8::1","RR":"test","Type":"AAAA"}]}}`)
	}))
	defer srv.Close()
	p := fixedAliyunProvider(srv.URL)
	op, err := p.Upsert(context.Background(), "chenos.cn", "test", "AAAA", "2001:db8::1", 600)
	if err != nil || op != "unchanged" {
		t.Fatalf("op=%s err=%v", op, err)
	}
	if len(queries) != 1 || queries[0].Get("Action") != "DescribeSubDomainRecords" || queries[0].Get("AccessKeyId") != "id" || queries[0].Get("Signature") == "" {
		t.Fatalf("queries=%v", queries)
	}
}

func TestAliyunCreated(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			io.WriteString(w, `{"DomainRecords":{"Record":[]}}`)
			return
		}
		if r.URL.Query().Get("Action") != "AddDomainRecord" {
			t.Fatalf("action=%s", r.URL.Query().Get("Action"))
		}
		io.WriteString(w, `{"RecordId":"r2"}`)
	}))
	defer srv.Close()
	p := fixedAliyunProvider(srv.URL)
	op, err := p.Upsert(context.Background(), "chenos.cn", "test", "AAAA", "2001:db8::2", 600)
	if err != nil || op != "created" || calls != 2 {
		t.Fatalf("op=%s calls=%d err=%v", op, calls, err)
	}
}

type errorDoer struct{}

func (errorDoer) Do(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: errors.New("network down")}
}

func TestAliyunTransportErrorDoesNotLeakSignedURL(t *testing.T) {
	p := fixedAliyunProvider("https://alidns.aliyuncs.com/")
	p.Client = errorDoer{}
	_, err := p.Upsert(context.Background(), "chenos.cn", "test", "AAAA", "2001:db8::1", 600)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, "AccessKeyId") || strings.Contains(msg, "Signature=") || strings.Contains(msg, "secret") || strings.Contains(msg, "alidns.aliyuncs.com/?") {
		t.Fatalf("credential-bearing URL leaked: %s", msg)
	}
	if !strings.Contains(msg, "network down") {
		t.Fatalf("message=%s", msg)
	}
}

func TestAliyunTXTDoesNotOverwriteUnrelatedValue(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		switch calls {
		case 1:
			io.WriteString(w, `{"DomainRecords":{"Record":[{"RecordId":"old","Value":"unrelated","RR":"_acme-challenge.test","Type":"TXT"}]}}`)
		case 2:
			if q.Get("Action") != "AddDomainRecord" || q.Get("Type") != "TXT" || q.Get("Value") != "challenge-value" {
				t.Fatalf("query=%v", q)
			}
			io.WriteString(w, `{"RecordId":"new"}`)
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer srv.Close()
	p := fixedAliyunProvider(srv.URL)
	op, err := p.Upsert(context.Background(), "chenos.cn", "_acme-challenge.test", "TXT", "challenge-value", 600)
	if err != nil || op != "created" || calls != 2 {
		t.Fatalf("op=%s calls=%d err=%v", op, calls, err)
	}
}

func TestAliyunDeleteExactTXTValue(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		switch calls {
		case 1:
			io.WriteString(w, `{"DomainRecords":{"Record":[{"RecordId":"keep","Value":"unrelated","RR":"_acme-challenge.test","Type":"TXT"},{"RecordId":"drop","Value":"challenge-value","RR":"_acme-challenge.test","Type":"TXT"}]}}`)
		case 2:
			if q.Get("Action") != "DeleteDomainRecord" || q.Get("RecordId") != "drop" {
				t.Fatalf("query=%v", q)
			}
			io.WriteString(w, `{}`)
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer srv.Close()
	p := fixedAliyunProvider(srv.URL)
	if err := p.Delete(context.Background(), "chenos.cn", "_acme-challenge.test", "TXT", "challenge-value"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestAliyunListZonesPaginatesAndSorts(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("Action") != "DescribeDomains" || q.Get("PageSize") != "100" {
			t.Fatalf("query=%v", q)
		}
		switch q.Get("PageNumber") {
		case "1":
			io.WriteString(w, `{"TotalCount":3,"PageNumber":1,"PageSize":100,"Domains":{"Domain":[{"DomainName":"z.example"},{"DomainName":"A.EXAMPLE."}]}}`)
		case "2":
			io.WriteString(w, `{"TotalCount":3,"PageNumber":2,"PageSize":100,"Domains":{"Domain":[{"DomainName":"m.example"}]}}`)
		default:
			t.Fatalf("unexpected page %s", q.Get("PageNumber"))
		}
	}))
	defer srv.Close()

	zones, err := fixedAliyunProvider(srv.URL).ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example", "m.example", "z.example"}
	if len(zones) != len(want) {
		t.Fatalf("zones=%v", zones)
	}
	for i := range want {
		if zones[i] != want[i] {
			t.Fatalf("zones=%v want=%v", zones, want)
		}
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestAliyunCapabilities(t *testing.T) {
	p := fixedAliyunProvider("https://alidns.aliyuncs.com/")
	if p.Name() != "aliyun" {
		t.Fatalf("name=%q", p.Name())
	}
	caps := p.Capabilities()
	if !caps.CredentialsValidation || !caps.DDNS || !caps.DNS01 || !caps.ZoneDiscovery {
		t.Fatalf("capabilities=%+v", caps)
	}
	want := []string{"credentials_validation", "ddns", "dns01", "zone_discovery"}
	got := caps.Names()
	if len(got) != len(want) {
		t.Fatalf("names=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names=%v want=%v", got, want)
		}
	}
}

func TestAliyunValidateCredentialsUsesReadOnlyDomainList(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("Action") != "DescribeDomains" || q.Get("PageNumber") != "1" || q.Get("PageSize") != "1" {
			t.Fatalf("query=%v", q)
		}
		io.WriteString(w, `{"TotalCount":1,"PageNumber":1,"PageSize":1,"Domains":{"Domain":[{"DomainName":"chenos.cn"}]}}`)
	}))
	defer srv.Close()
	if err := fixedAliyunProvider(srv.URL).ValidateCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestAliyunMissingCredentialsAreAuthenticationError(t *testing.T) {
	p := &AliyunProvider{}
	_, err := p.ListZones(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	kind, retryable, code := ErrorDetails(err)
	if kind != ErrorAuthentication || retryable || code != "credentials_missing" {
		t.Fatalf("kind=%s retryable=%v code=%q err=%v", kind, retryable, code, err)
	}
}

func TestAliyunAPIErrorClassification(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		kind      ErrorKind
		retryable bool
		code      string
	}{
		{"auth", http.StatusBadRequest, `{"Code":"SignatureDoesNotMatch","Message":"bad signature"}`, ErrorAuthentication, false, "SignatureDoesNotMatch"},
		{"rate", http.StatusTooManyRequests, `{"Code":"Throttling.User","Message":"slow down"}`, ErrorRateLimit, true, "Throttling.User"},
		{"zone", http.StatusBadRequest, `{"Code":"DomainNotFound","Message":"domain missing"}`, ErrorInvalidZone, false, "DomainNotFound"},
		{"temporary", http.StatusServiceUnavailable, `{"Code":"ServiceUnavailable","Message":"try later"}`, ErrorTemporary, true, "ServiceUnavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			_, err := fixedAliyunProvider(srv.URL).ListZones(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			kind, retryable, code := ErrorDetails(err)
			if kind != tc.kind || retryable != tc.retryable || code != tc.code {
				t.Fatalf("kind=%s retryable=%v code=%q err=%v", kind, retryable, code, err)
			}
		})
	}
}

func TestAliyunAuthenticationResponseMessageIsSanitized(t *testing.T) {
	const leakedID = "LTAI5t9spkAHEedHYXwPsNis"
	const leakedNonce = "deadbeefcafebabe"
	const leakedSignature = "abc123secretish=="
	body := `{"Code":"SignatureDoesNotMatch","Message":"Specified signature is not matched. server string to sign is: GET&%2F&AccessKeyId%3D` + leakedID + `%26Signature%3D` + leakedSignature + `%26SignatureNonce%3D` + leakedNonce + `"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	_, err := fixedAliyunProvider(srv.URL).ListZones(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	kind, retryable, code := ErrorDetails(err)
	if kind != ErrorAuthentication || retryable || code != "SignatureDoesNotMatch" {
		t.Fatalf("kind=%s retryable=%v code=%q err=%v", kind, retryable, code, err)
	}
	msg := err.Error()
	for _, forbidden := range []string{leakedID, leakedNonce, leakedSignature, "AccessKeyId", "SignatureNonce", "string to sign"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("provider response leaked signed request material %q: %s", forbidden, msg)
		}
	}
	if !strings.Contains(msg, "request signature was rejected") {
		t.Fatalf("missing safe authentication diagnostic: %s", msg)
	}
}

func TestAliyunNonAuthSensitiveMessageFallsBackToGenericDiagnostic(t *testing.T) {
	err := classifyAliyunCode("zones.list", http.StatusBadRequest, "SomeNewCode", "debug AccessKeyId=AKID Signature=SIG SignatureNonce=NONCE")
	if strings.Contains(err.Error(), "AKID") || strings.Contains(err.Error(), "SIG") || strings.Contains(err.Error(), "NONCE") || strings.Contains(err.Error(), "AccessKeyId") {
		t.Fatalf("sensitive remote diagnostic leaked: %s", err)
	}
	if !strings.Contains(err.Error(), "Aliyun DNS API rejected the request") {
		t.Fatalf("unexpected sanitized diagnostic: %s", err)
	}
}

func TestAliyunContextCancellationIsClassified(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := fixedAliyunProvider("https://alidns.aliyuncs.com/")
	_, err := p.ListZones(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
	kind, retryable, _ := ErrorDetails(err)
	if kind != ErrorContextCanceled || retryable {
		t.Fatalf("kind=%s retryable=%v err=%v", kind, retryable, err)
	}
	if strings.Contains(err.Error(), "AccessKeyId") || strings.Contains(err.Error(), "Signature=") {
		t.Fatalf("credential-bearing URL leaked: %s", err)
	}
}
