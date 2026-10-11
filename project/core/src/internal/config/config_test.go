package config

import (
	"strings"
	"testing"
)

func TestParseR6CompatibleMain(t *testing.T) {
	in := `homegate.main=homegate
homegate.main.enabled='1'
homegate.main.log_level='info'
homegate.main.log_max_lines='1024'
homegate.main.log_capture_errors='1'
homegate.main.wol_interface='br-lan'
homegate.ddns_test=ddns_rule
homegate.ddns_test.enabled='0'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured || !got.Main.Enabled {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if got.Main.LogLevel != "info" || got.Main.LogMaxLines != 1024 || !got.Main.LogCaptureErrors || got.Main.WOLInterface != "br-lan" {
		t.Fatalf("unexpected logging config: %+v", got.Main)
	}
}

func TestParseDisabled(t *testing.T) {
	got, err := ParseShow("homegate.main=homegate\nhomegate.main.enabled='0'\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.Enabled {
		t.Fatal("disabled config reported enabled")
	}
}

func TestParseMissingMain(t *testing.T) {
	if _, err := ParseShow("homegate.foo=wol_host\n"); err == nil {
		t.Fatal("expected missing-main error")
	}
}

func TestParseInvalidKnownValue(t *testing.T) {
	if _, err := ParseShow("homegate.main=homegate\nhomegate.main.log_level='verbose'\n"); err == nil {
		t.Fatal("expected invalid log level error")
	}
}

func TestParseR6AliyunDDNS(t *testing.T) {
	in := `homegate.main=homegate
homegate.main.enabled='1'
homegate.main.ddns_interval='300'
homegate.dns_26e7f2e39793=dns_account
homegate.dns_26e7f2e39793.name='Aliyun'
homegate.dns_26e7f2e39793.provider='aliyun'
homegate.dns_26e7f2e39793.id='key-id'
homegate.dns_26e7f2e39793.secret='key-secret'
homegate.ddns_1db14129c46f=ddns_rule
homegate.ddns_1db14129c46f.enabled='1'
homegate.ddns_1db14129c46f.name='test.chenos.cn'
homegate.ddns_1db14129c46f.account='dns_26e7f2e39793'
homegate.ddns_1db14129c46f.type='AAAA'
homegate.ddns_1db14129c46f.source='auto'
homegate.ddns_1db14129c46f.zone='chenos.cn'
homegate.ddns_1db14129c46f.host='test'
homegate.ddns_1db14129c46f.ttl='600'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.DDNSInterval != 300 {
		t.Fatalf("interval=%d", got.Main.DDNSInterval)
	}
	acc, ok := got.Accounts["dns_26e7f2e39793"]
	if !ok || acc.Provider != "aliyun" || acc.KeyID != "key-id" || acc.Secret != "key-secret" {
		t.Fatalf("account=%+v ok=%v", acc, ok)
	}
	if len(got.DDNS) != 1 {
		t.Fatalf("rules=%d", len(got.DDNS))
	}
	r := got.DDNS[0]
	if r.ID != "ddns_1db14129c46f" || !r.Enabled || r.Account != acc.ID || r.Zone != "chenos.cn" || r.Host != "test" || r.Type != "AAAA" || r.Source != "auto" || r.TTL != 600 {
		t.Fatalf("rule=%+v", r)
	}
}

func TestDDNSIntervalKeepsR6Minimum(t *testing.T) {
	got, err := ParseShow("homegate.main=homegate\nhomegate.main.ddns_interval='10'\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.DDNSInterval != 60 {
		t.Fatalf("interval=%d want 60", got.Main.DDNSInterval)
	}
}

func TestParseR6CertificateAndACME(t *testing.T) {
	in := `homegate.main=homegate
homegate.main.enabled='1'
homegate.main.acme_email='ops@example.com'
homegate.main.acme_directory='https://acme-staging-v02.api.letsencrypt.org/directory'
homegate.main.renew_days='30'
homegate.dns_26e7f2e39793=dns_account
homegate.dns_26e7f2e39793.provider='aliyun'
homegate.dns_26e7f2e39793.id='key-id'
homegate.dns_26e7f2e39793.secret='key-secret'
homegate.cert_c00a05d1c203=certificate
homegate.cert_c00a05d1c203.enabled='1'
homegate.cert_c00a05d1c203.name='test'
homegate.cert_c00a05d1c203.source='local'
homegate.cert_c00a05d1c203.account='dns_26e7f2e39793'
homegate.cert_c00a05d1c203.zone='chenos.cn'
homegate.cert_c00a05d1c203.domains='test.chenos.cn'
homegate.cert_c00a05d1c203.renew_days='30'
homegate.cert_c00a05d1c203.environment='staging'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.ACMEEmail != "ops@example.com" || got.Main.ACMEDirectory != "https://acme-staging-v02.api.letsencrypt.org/directory" || got.Main.RenewDays != 30 {
		t.Fatalf("main=%+v", got.Main)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("certs=%d", len(got.Certificates))
	}
	c := got.Certificates[0]
	if c.ID != "cert_c00a05d1c203" || !c.Enabled || c.Source != "local" || c.Account != "dns_26e7f2e39793" || c.Zone != "chenos.cn" || len(c.Domains) != 1 || c.Domains[0] != "test.chenos.cn" || c.RenewDays != 30 || c.Environment != CertificateEnvStaging {
		t.Fatalf("cert=%+v", c)
	}
}

func TestCertificateSourceAndEnvironmentDefaults(t *testing.T) {
	got, err := ParseShow("homegate.main=homegate\nhomegate.main.acme_directory='https://acme-staging-v02.api.letsencrypt.org/directory'\nhomegate.c=certificate\nhomegate.c.domains='test.example.com'\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificates) != 1 || got.Certificates[0].Source != "acme" || got.Certificates[0].Environment != CertificateEnvProduction {
		t.Fatalf("certificates=%+v", got.Certificates)
	}
	if _, err := ParseShow("homegate.main=homegate\nhomegate.c=certificate\nhomegate.c.source='other'\nhomegate.c.domains='test.example.com'\n"); err == nil {
		t.Fatal("expected invalid certificate source")
	}
	if _, err := ParseShow("homegate.main=homegate\nhomegate.c=certificate\nhomegate.c.environment='other'\nhomegate.c.domains='test.example.com'\n"); err == nil {
		t.Fatal("expected invalid certificate environment")
	}
}

func TestCertificateACMEDirectory(t *testing.T) {
	if got := CertificateACMEDirectory(CertificateEnvProduction); got != DefaultACMEDirectory {
		t.Fatalf("production directory=%q", got)
	}
	if got := CertificateACMEDirectory(CertificateEnvStaging); got != StagingACMEDirectory {
		t.Fatalf("staging directory=%q", got)
	}
}

func TestParseCertificateDomainList(t *testing.T) {
	in := `homegate.main=homegate
homegate.c=certificate
homegate.c.account='dns'
homegate.c.zone='example.com'
homegate.c.domain='example.com'
homegate.c.domain='*.example.com'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificates) != 1 || len(got.Certificates[0].Domains) != 2 || got.Certificates[0].Domains[1] != "*.example.com" {
		t.Fatalf("certs=%+v", got.Certificates)
	}
}

func TestParseR6WebAndFirewall(t *testing.T) {
	in := `homegate.main=homegate
homegate.main.enabled='1'
homegate.main.https_port='443'
homegate.main.http_port='0'
homegate.main.proxy_https_port='10443'
homegate.main.proxy_http_port='10080'
homegate.main.auto_firewall='1'
homegate.web_fe773d310ea2=web_rule
homegate.web_fe773d310ea2.enabled='1'
homegate.web_fe773d310ea2.domain='test.chenos.cn'
homegate.web_fe773d310ea2.target='http://192.168.2.3'
homegate.web_fe773d310ea2.https='1'
homegate.web_fe773d310ea2.certificate='cert_c00a05d1c203'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.HTTPSPort != 443 || got.Main.HTTPPort != 0 || got.Main.ProxyHTTPSPort != 10443 || got.Main.ProxyHTTPPort != 10080 || !got.Main.AutoFirewall {
		t.Fatalf("main=%+v", got.Main)
	}
	if len(got.Web) != 1 {
		t.Fatalf("web=%d", len(got.Web))
	}
	r := got.Web[0]
	if r.ID != "web_fe773d310ea2" || !r.Enabled || r.Domain != "test.chenos.cn" || r.Target != "http://192.168.2.3" || !r.HTTPS || r.Certificate != "cert_c00a05d1c203" {
		t.Fatalf("rule=%+v", r)
	}
}

func TestInvalidProxyPortRejected(t *testing.T) {
	if _, err := ParseShow("homegate.main=homegate\nhomegate.main.proxy_https_port='70000'\n"); err == nil {
		t.Fatal("expected port error")
	}
}

func TestInvalidEnabledWebTargetRejected(t *testing.T) {
	in := "homegate.main=homegate\nhomegate.web1=web_rule\nhomegate.web1.enabled='1'\nhomegate.web1.domain='x.example'\nhomegate.web1.target='bad'\n"
	if _, err := ParseShow(in); err == nil {
		t.Fatal("expected invalid target")
	}
}

func TestDisabledInvalidWebTargetPreserved(t *testing.T) {
	in := "homegate.main=homegate\nhomegate.web1=web_rule\nhomegate.web1.enabled='0'\nhomegate.web1.domain='x.example'\nhomegate.web1.target='bad'\n"
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Web) != 1 || got.Web[0].Enabled {
		t.Fatalf("web=%+v", got.Web)
	}
}

func TestParseR6WOLHosts(t *testing.T) {
	in := `homegate.main=homegate
homegate.main.enabled='1'
homegate.main.wol_interface='br-lan'
homegate.main.last_wol_host='wol_pve'
homegate.wol_z=wol_host
homegate.wol_z.name='Desktop'
homegate.wol_z.mac='aa:bb:cc:dd:ee:ff'
homegate.wol_pve=wol_host
homegate.wol_pve.name='PVE'
homegate.wol_pve.mac='c8:7f:54:53:6b:80'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Main.WOLInterface != "br-lan" || got.Main.LastWOLHost != "wol_pve" {
		t.Fatalf("main=%+v", got.Main)
	}
	if len(got.WOL) != 2 {
		t.Fatalf("wol=%+v", got.WOL)
	}
	if got.WOL[0].ID != "wol_pve" || got.WOL[0].Name != "PVE" || got.WOL[0].MAC != "C8:7F:54:53:6B:80" {
		t.Fatalf("first=%+v", got.WOL[0])
	}
	if got.WOL[1].ID != "wol_z" || got.WOL[1].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("second=%+v", got.WOL[1])
	}
}

func TestHTTPSWebRuleRequiresProxyHTTPPortForRedirect(t *testing.T) {
	raw := "" +
		"homegate.main=homegate\n" +
		"homegate.main.proxy_https_port='10443'\n" +
		"homegate.main.proxy_http_port='0'\n" +
		"homegate.web1=web_rule\n" +
		"homegate.web1.enabled='1'\n" +
		"homegate.web1.domain='test.example.com'\n" +
		"homegate.web1.target='http://192.168.2.3'\n" +
		"homegate.web1.https='1'\n"
	if _, err := ParseShow(raw); err == nil || !strings.Contains(err.Error(), "proxy_http_port for HTTP-to-HTTPS redirect") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseAccessRestrictionDualStack(t *testing.T) {
	in := "homegate.main=homegate\n" +
		"homegate.main.access_enabled='1'\n" +
		"homegate.main.access_allow='192.0.2.7, 2001:db8::/32'\n" +
		"homegate.main.access_deny='198.51.100.9/32, 2001:db9::9/128'\n" +
		"homegate.main.access_region='CN-GD'\n"
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Main.AccessEnabled || got.Main.AccessAllow != "192.0.2.7, 2001:db8::/32" || got.Main.AccessDeny != "198.51.100.9/32, 2001:db9::9/128" || got.Main.AccessRegion != "" || got.Main.RetiredAccessRegion != "CN-GD" {
		t.Fatalf("main=%+v", got.Main)
	}
}

func TestParseAccessRestrictionAllowsEmptyManualFailClosed(t *testing.T) {
	got, err := ParseShow("homegate.main=homegate\nhomegate.main.access_enabled='1'\n")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Main.AccessEnabled || got.Main.AccessAllow != "" || got.Main.AccessRegion != "" {
		t.Fatalf("main=%+v", got.Main)
	}
}

func TestParseAccessRestrictionRejectsInvalidCIDR(t *testing.T) {
	if _, err := ParseShow("homegate.main=homegate\nhomegate.main.access_enabled='1'\nhomegate.main.access_allow='192.0.2.999'\n"); err == nil {
		t.Fatal("expected invalid access IP error")
	}
}

func TestParseAccessRestrictionRejectsInvalidDenyCIDR(t *testing.T) {
	if _, err := ParseShow("homegate.main=homegate\nhomegate.main.access_enabled='1'\nhomegate.main.access_deny='2001:db8::zz/128'\n"); err == nil {
		t.Fatal("expected invalid access deny IP error")
	}
}

func TestParseProviderNeutralCredentialsAndCAFields(t *testing.T) {
	in := `homegate.main=homegate
homegate.h=dns_account
homegate.h.provider='huaweicloud'
homegate.h.id='ak'
homegate.h.secret='sk'
homegate.h.account_id='domain-id'
homegate.h.endpoint='https://dns.example'
homegate.c=certificate
homegate.c.account='h'
homegate.c.zone='example.com'
homegate.c.domains='example.com'
homegate.c.ca='letsencrypt'
homegate.c.environment='staging'
`
	got, err := ParseShow(in)
	if err != nil {
		t.Fatal(err)
	}
	a := got.Accounts["h"]
	if a.Provider != "huaweicloud" || a.AccountID != "domain-id" || a.Endpoint != "https://dns.example" {
		t.Fatalf("account=%+v", a)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("certs=%v", got.Certificates)
	}
	c := got.Certificates[0]
	if c.CA != "letsencrypt" || c.Environment != "staging" {
		t.Fatalf("cert=%+v", c)
	}
}

func TestCertificateRejectsRemovedCustomEnvironment(t *testing.T) {
	_, err := ParseShow("homegate.main=homegate\nhomegate.c=certificate\nhomegate.c.domains='test.example.com'\nhomegate.c.environment='custom'\n")
	if err == nil {
		t.Fatal("expected removed custom ACME environment rejection")
	}
}

func TestPre11CertificateMigratesToLetsEncrypt(t *testing.T) {
	got, err := ParseShow("homegate.main=homegate\nhomegate.c=certificate\nhomegate.c.domains='test.example.com'\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificates) != 1 || got.Certificates[0].CA != "letsencrypt" || got.Certificates[0].Environment != CertificateEnvProduction {
		t.Fatalf("certificates=%+v", got.Certificates)
	}
}
