package acmeca

import (
	"fmt"
	"sort"
	"strings"
)

const (
	EnvironmentProduction = "production"
	EnvironmentStaging    = "staging"

	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Preset struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Directories map[string]string `json:"directories,omitempty"`
}

type Selection struct {
	CA          string `json:"ca"`
	Environment string `json:"environment"`
	Directory   string `json:"directory"`
}

var presets = []Preset{
	{
		Name: "letsencrypt", DisplayName: "Let's Encrypt",
		Directories: map[string]string{
			EnvironmentProduction: LetsEncryptProduction,
			EnvironmentStaging:    LetsEncryptStaging,
		},
	},
}

func Presets() []Preset {
	out := make([]Preset, len(presets))
	for i, p := range presets {
		out[i] = p
		if p.Directories != nil {
			out[i].Directories = make(map[string]string, len(p.Directories))
			for k, v := range p.Directories {
				out[i].Directories[k] = v
			}
		}
	}
	return out
}

func Names() []string {
	out := make([]string, 0, len(presets))
	for _, p := range presets {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func PresetFor(name string) (Preset, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "le" {
		name = "letsencrypt"
	}
	for _, p := range presets {
		if p.Name == name {
			copy := p
			if p.Directories != nil {
				copy.Directories = make(map[string]string, len(p.Directories))
				for k, v := range p.Directories {
					copy.Directories[k] = v
				}
			}
			return copy, true
		}
	}
	return Preset{}, false
}

// Resolve validates a certificate-resource CA selection and resolves its fixed
// ACME directory. Blank CA remains Let's Encrypt for 1.0.x migration.
// HomeGate intentionally exposes only release-tested direct-connect CA
// endpoints; users who need another issuer can import a local certificate/key.
func Resolve(ca, environment string) (Selection, error) {
	p, ok := PresetFor(ca)
	if !ok {
		return Selection{}, fmt.Errorf("unsupported ACME CA %q", strings.TrimSpace(ca))
	}
	env := strings.ToLower(strings.TrimSpace(environment))
	if env == "" {
		env = EnvironmentProduction
	}
	dir, ok := p.Directories[env]
	if !ok || strings.TrimSpace(dir) == "" {
		return Selection{}, fmt.Errorf("ACME CA %s does not support environment %s", p.Name, env)
	}
	return Selection{CA: p.Name, Environment: env, Directory: dir}, nil
}
