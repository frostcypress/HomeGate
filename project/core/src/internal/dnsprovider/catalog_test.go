package dnsprovider

import (
	"testing"

	"homegate.local/homegate/internal/config"
)

func TestCatalogCredentialShapesAndAliases(t *testing.T) {
	if CanonicalName("CF") != "cloudflare" || CanonicalName("tencentcloud") != "dnspod" || CanonicalName("huawei") != "huaweicloud" {
		t.Fatal("provider aliases are not canonicalized")
	}
	cases := []config.DNSAccount{
		{Provider: "aliyun", KeyID: "ak", Secret: "sk"},
		{Provider: "cloudflare", Secret: "token"},
		{Provider: "dnspod", KeyID: "sid", Secret: "skey"},
		{Provider: "huaweicloud", KeyID: "ak", Secret: "sk", AccountID: "domain", Endpoint: "https://dns.example"},
	}
	for _, account := range cases {
		if err := ValidateCredentialShape(account); err != nil {
			t.Fatalf("%s shape rejected: %v", account.Provider, err)
		}
		p, err := New(account)
		if err != nil || p.Name() != CanonicalName(account.Provider) {
			t.Fatalf("%s factory p=%v err=%v", account.Provider, p, err)
		}
	}
	if err := ValidateCredentialShape(config.DNSAccount{Provider: "huaweicloud", KeyID: "ak", Secret: "sk", AccountID: "domain"}); err == nil {
		t.Fatal("Huawei endpoint must be explicit")
	}
}

func TestCatalogDoesNotContainCredentialValues(t *testing.T) {
	for _, d := range Definitions() {
		for _, f := range d.Credentials {
			if f.Name == "secret" && !f.Secret {
				t.Fatalf("%s secret field not marked secret", d.Name)
			}
		}
	}
}
