package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var b64raw = base64.RawURLEncoding

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type order struct {
	Status         string       `json:"status"`
	Identifiers    []identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          any          `json:"error,omitempty"`
}

type challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
	Error  any    `json:"error,omitempty"`
}

type authorization struct {
	Status     string      `json:"status"`
	Identifier identifier  `json:"identifier"`
	Wildcard   bool        `json:"wildcard"`
	Challenges []challenge `json:"challenges"`
	Error      any         `json:"error,omitempty"`
}

type account struct {
	Status string `json:"status"`
}

type accountState struct {
	Directory     string `json:"directory"`
	KID           string `json:"kid"`
	JWKThumbprint string `json:"jwk_thumbprint"`
}

type client struct {
	dir              directory
	dirURL           string
	key              *ecdsa.PrivateKey
	kid              string
	nonce            string
	http             HTTPDoer
	accountStatePath string
}

func defaultHTTPClient() HTTPDoer {
	// HomeGate automatic certificate management is a direct-connect feature.
	// Never inherit HTTP_PROXY/HTTPS_PROXY from the router environment: release
	// support is gated on the CA being reachable without an application proxy.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func ecdsaKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("ACME account key PEM is invalid")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ACME account key must use P-256 for ES256")
		}
		return k, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func jwk(k *ecdsa.PrivateKey) map[string]string {
	xb, yb := k.PublicKey.X.Bytes(), k.PublicKey.Y.Bytes()
	x, y := make([]byte, 32), make([]byte, 32)
	copy(x[32-len(xb):], xb)
	copy(y[32-len(yb):], yb)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64raw.EncodeToString(x), "y": b64raw.EncodeToString(y)}
}

func jwkThumbprint(k *ecdsa.PrivateKey) string {
	j := jwk(k)
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j["crv"], j["kty"], j["x"], j["y"])
	h := sha256.Sum256([]byte(canonical))
	return b64raw.EncodeToString(h[:])
}

func signES256(k *ecdsa.PrivateKey, data string) (string, error) {
	h := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return b64raw.EncodeToString(out), nil
}

func requestJSON(ctx context.Context, h HTTPDoer, method, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	resp, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("ACME directory request failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ACME directory HTTP %d", resp.StatusCode)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("ACME directory JSON: %w", err)
		}
	}
	return nil
}

func newClient(ctx context.Context, dirURL, keyPath string, h HTTPDoer) (*client, error) {
	if strings.TrimSpace(dirURL) == "" {
		return nil, fmt.Errorf("ACME directory is empty")
	}
	if h == nil {
		h = defaultHTTPClient()
	}
	var d directory
	if err := requestJSON(ctx, h, http.MethodGet, dirURL, &d); err != nil {
		return nil, err
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return nil, fmt.Errorf("ACME directory is incomplete")
	}
	k, err := ecdsaKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &client{dir: d, dirURL: dirURL, key: k, http: h}, nil
}

func (c *client) getNonce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ACME nonce request failed: %v", err)
	}
	defer resp.Body.Close()
	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		return fmt.Errorf("ACME did not return Replay-Nonce")
	}
	return nil
}

func (c *client) jwsOnce(ctx context.Context, u string, payload any, useJWK bool) ([]byte, http.Header, error, bool) {
	if c.nonce == "" {
		if err := c.getNonce(ctx); err != nil {
			return nil, nil, err, false
		}
	}
	protected := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": u}
	if useJWK {
		protected["jwk"] = jwk(c.key)
	} else {
		if c.kid == "" {
			return nil, nil, fmt.Errorf("ACME account KID is empty"), false
		}
		protected["kid"] = c.kid
	}
	pb, err := json.Marshal(protected)
	if err != nil {
		return nil, nil, err, false
	}
	var payloadBytes []byte
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, err, false
		}
	}
	p64, d64 := b64raw.EncodeToString(pb), b64raw.EncodeToString(payloadBytes)
	sig, err := signES256(c.key, p64+"."+d64)
	if err != nil {
		return nil, nil, err, false
	}
	body, _ := json.Marshal(map[string]string{"protected": p64, "payload": d64, "signature": sig})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err, false
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("ACME request failed: %v", err), false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
		c.nonce = nonce
	} else {
		c.nonce = ""
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		badNonce := strings.Contains(string(data), "urn:ietf:params:acme:error:badNonce")
		return nil, resp.Header, fmt.Errorf("ACME HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data))), badNonce
	}
	return data, resp.Header, nil, false
}

func (c *client) jws(ctx context.Context, u string, payload any, useJWK bool) ([]byte, http.Header, error) {
	data, h, err, bad := c.jwsOnce(ctx, u, payload, useJWK)
	if err != nil && bad {
		data, h, err, _ = c.jwsOnce(ctx, u, payload, useJWK)
	}
	return data, h, err
}

func (c *client) loadAccountState() bool {
	if strings.TrimSpace(c.accountStatePath) == "" {
		return false
	}
	b, err := os.ReadFile(c.accountStatePath)
	if err != nil {
		return false
	}
	var st accountState
	if json.Unmarshal(b, &st) != nil || strings.TrimSpace(st.KID) == "" {
		return false
	}
	if st.Directory != c.dirURL || st.JWKThumbprint != jwkThumbprint(c.key) {
		return false
	}
	c.kid = st.KID
	return true
}

func (c *client) saveAccountState() error {
	if strings.TrimSpace(c.accountStatePath) == "" {
		return nil
	}
	st := accountState{Directory: c.dirURL, KID: c.kid, JWKThumbprint: jwkThumbprint(c.key)}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicWrite(c.accountStatePath, append(b, '\n'), 0600)
}

func (c *client) ensureAccount(ctx context.Context, email string) error {
	if c.loadAccountState() {
		return nil
	}
	payload := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	data, h, err := c.jws(ctx, c.dir.NewAccount, payload, true)
	if err != nil {
		return err
	}
	var a account
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	c.kid = h.Get("Location")
	if c.kid == "" {
		return fmt.Errorf("ACME did not return account Location")
	}
	if err := c.saveAccountState(); err != nil {
		return fmt.Errorf("persist ACME account state: %w", err)
	}
	return nil
}

func (c *client) postJSONHeader(ctx context.Context, u string, payload, out any) (http.Header, error) {
	data, h, err := c.jws(ctx, u, payload, false)
	if err != nil {
		return h, err
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return h, err
		}
	}
	return h, nil
}
func (c *client) postJSON(ctx context.Context, u string, payload, out any) error {
	_, err := c.postJSONHeader(ctx, u, payload, out)
	return err
}
func (c *client) postAsGet(ctx context.Context, u string, out any) error {
	return c.postJSON(ctx, u, nil, out)
}
func (c *client) postAsGetRaw(ctx context.Context, u string) ([]byte, error) {
	data, _, err := c.jws(ctx, u, nil, false)
	return data, err
}
