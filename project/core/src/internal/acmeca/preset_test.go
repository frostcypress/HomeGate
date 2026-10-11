package acmeca

import "testing"

func TestResolveMigrationAndLetsEncryptPresets(t *testing.T) {
	cases := []struct {
		ca, env, wantDir string
	}{
		{"", "", LetsEncryptProduction},
		{"letsencrypt", "production", LetsEncryptProduction},
		{"letsencrypt", "staging", LetsEncryptStaging},
		{"le", "production", LetsEncryptProduction},
	}
	for _, tc := range cases {
		sel, err := Resolve(tc.ca, tc.env)
		if err != nil {
			t.Fatalf("Resolve(%q,%q): %v", tc.ca, tc.env, err)
		}
		if sel.CA != "letsencrypt" || sel.Directory != tc.wantDir {
			t.Fatalf("Resolve(%q,%q)=%+v", tc.ca, tc.env, sel)
		}
	}
}

func TestResolveRejectsRemovedCAsAndInvalidEnvironment(t *testing.T) {
	for _, ca := range []string{"zerossl", "google", "custom"} {
		if _, err := Resolve(ca, "production"); err == nil {
			t.Fatalf("expected removed CA %q rejection", ca)
		}
	}
	if _, err := Resolve("letsencrypt", "custom"); err == nil {
		t.Fatal("expected invalid environment rejection")
	}
}
