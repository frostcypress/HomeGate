package dnsprovider

import (
	"sort"
	"strings"

	"homegate.local/homegate/internal/config"
)

// CredentialField describes one provider credential input. Secret fields must
// never be returned with their stored values; this metadata is safe for CLI/UI.
type CredentialField struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
}

// Definition is provider-neutral metadata used by Core, CLI and LuCI. Vendor
// API behavior stays in concrete providers; UI only consumes this catalog.
type Definition struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name"`
	Aliases      []string          `json:"aliases,omitempty"`
	Capabilities Capabilities      `json:"capabilities"`
	Credentials  []CredentialField `json:"credentials"`
}

var definitions = []Definition{
	{
		Name: "aliyun", DisplayName: "Aliyun DNS", Aliases: []string{"alidns"},
		Capabilities: Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true},
		Credentials: []CredentialField{
			{Name: "key_id", Label: "AccessKey ID", Required: true},
			{Name: "secret", Label: "AccessKey Secret", Secret: true, Required: true},
		},
	},
	{
		Name: "cloudflare", DisplayName: "Cloudflare", Aliases: []string{"cf"},
		Capabilities: Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true},
		Credentials: []CredentialField{
			{Name: "secret", Label: "API Token", Secret: true, Required: true},
		},
	},
	{
		Name: "dnspod", DisplayName: "Tencent DNSPod", Aliases: []string{"tencent", "tencentcloud"},
		Capabilities: Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true},
		Credentials: []CredentialField{
			{Name: "key_id", Label: "SecretId", Required: true},
			{Name: "secret", Label: "SecretKey", Secret: true, Required: true},
		},
	},
	{
		Name: "huaweicloud", DisplayName: "Huawei Cloud DNS", Aliases: []string{"huawei", "hwcloud"},
		Capabilities: Capabilities{CredentialsValidation: true, DDNS: true, DNS01: true, ZoneDiscovery: true},
		Credentials: []CredentialField{
			{Name: "key_id", Label: "Access Key ID", Required: true},
			{Name: "secret", Label: "Secret Access Key", Secret: true, Required: true},
			{Name: "account_id", Label: "Account ID", Required: true},
			{Name: "endpoint", Label: "DNS API Endpoint", Required: true, Placeholder: "https://dns.<region>.myhuaweicloud.com"},
		},
	},
}

func Definitions() []Definition {
	out := make([]Definition, len(definitions))
	copy(out, definitions)
	for i := range out {
		out[i].Aliases = append([]string(nil), out[i].Aliases...)
		out[i].Credentials = append([]CredentialField(nil), out[i].Credentials...)
	}
	return out
}

func CanonicalName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, d := range definitions {
		if name == d.Name {
			return d.Name
		}
		for _, alias := range d.Aliases {
			if name == alias {
				return d.Name
			}
		}
	}
	return name
}

func DefinitionFor(name string) (Definition, bool) {
	name = CanonicalName(name)
	for _, d := range definitions {
		if d.Name == name {
			return d, true
		}
	}
	return Definition{}, false
}

func ValidateCredentialShape(account config.DNSAccount) error {
	d, ok := DefinitionFor(account.Provider)
	if !ok {
		return NewError(strings.TrimSpace(account.Provider), "initialize", ErrorUnsupported, "", "DNS provider is not supported by the current Core", false, nil)
	}
	values := map[string]string{
		"key_id": account.KeyID, "secret": account.Secret,
		"account_id": account.AccountID, "endpoint": account.Endpoint,
	}
	missing := make([]string, 0)
	for _, field := range d.Credentials {
		if field.Required && strings.TrimSpace(values[field.Name]) == "" {
			missing = append(missing, field.Label)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return NewError(d.Name, "initialize", ErrorAuthentication, "credentials_missing", "missing required credentials: "+strings.Join(missing, ", "), false, nil)
	}
	return nil
}

// New resolves a configured account into the unified provider contract.
func New(account config.DNSAccount) (Provider, error) {
	if err := ValidateCredentialShape(account); err != nil {
		return nil, err
	}
	switch CanonicalName(account.Provider) {
	case "aliyun":
		return &AliyunProvider{AccessKeyID: account.KeyID, AccessKeySecret: account.Secret}, nil
	case "cloudflare":
		return &CloudflareProvider{Token: account.Secret}, nil
	case "dnspod":
		return &DNSPodProvider{SecretID: account.KeyID, SecretKey: account.Secret}, nil
	case "huaweicloud":
		return &HuaweiCloudProvider{AccessKey: account.KeyID, SecretKey: account.Secret, AccountID: account.AccountID, Endpoint: account.Endpoint}, nil
	default:
		return nil, NewError(strings.TrimSpace(account.Provider), "initialize", ErrorUnsupported, "", "DNS provider is not supported by the current Core", false, nil)
	}
}
