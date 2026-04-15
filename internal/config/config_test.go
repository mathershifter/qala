package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.aristanetworks.com/jmather/qala/internal/config"
)

// TestDefaults verifies that all five Config fields carry the correct
// built-in default values as specified in SPEC.md §10.2.
func TestDefaults(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		got       func(config.Config) any
		wantStr   string
		wantInt   int
		isString  bool
	}{
		{
			name:     "CAOrg is Qala CA",
			field:    "CAOrg",
			got:      func(c config.Config) any { return c.CAOrg },
			wantStr:  "Qala CA",
			isString: true,
		},
		{
			name:     "CACNRoot is Qala Root CA",
			field:    "CACNRoot",
			got:      func(c config.Config) any { return c.CACNRoot },
			wantStr:  "Qala Root CA",
			isString: true,
		},
		{
			name:     "CACNIntermediate is Qala Intermediate CA",
			field:    "CACNIntermediate",
			got:      func(c config.Config) any { return c.CACNIntermediate },
			wantStr:  "Qala Intermediate CA",
			isString: true,
		},
		{
			name:     "CertOrg is Qala Default OU",
			field:    "CertOrg",
			got:      func(c config.Config) any { return c.CertOrg },
			wantStr:  "Qala Default OU",
			isString: true,
		},
		{
			name:    "DefaultValidityDays is 365",
			field:   "DefaultValidityDays",
			got:     func(c config.Config) any { return c.DefaultValidityDays },
			wantInt: 365,
		},
	}

	cfg := config.Defaults()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.got(cfg)
			if tt.isString {
				if got.(string) != tt.wantStr {
					t.Errorf("%s: got %q, want %q", tt.field, got, tt.wantStr)
				}
			} else {
				if got.(int) != tt.wantInt {
					t.Errorf("%s: got %d, want %d", tt.field, got, tt.wantInt)
				}
			}
		})
	}
}

// TestSave_Load_RoundTrip verifies that a Config written with Save can be read
// back with Load and produces an identical struct.
func TestSave_Load_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
	}{
		{
			name: "defaults round-trip",
			cfg:  config.Defaults(),
		},
		{
			name: "custom values round-trip",
			cfg: config.Config{
				CAOrg:               "My CA Org",
				CACNRoot:            "My Root",
				CACNIntermediate:    "My Intermediate",
				CertOrg:             "My Cert OU",
				DefaultValidityDays: 90,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if err := config.Save(dir, tt.cfg); err != nil {
				t.Fatalf("Save: %v", err)
			}

			loaded, err := config.Load(dir)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if loaded != tt.cfg {
				t.Errorf("loaded config does not match saved config\ngot:  %+v\nwant: %+v", loaded, tt.cfg)
			}
		})
	}
}

// TestLoad_MissingFile_ReturnsDefaults verifies that Load on a directory with
// no config.json returns the built-in defaults without error.
func TestLoad_MissingFile_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load on empty dir: unexpected error: %v", err)
	}

	want := config.Defaults()
	if cfg != want {
		t.Errorf("expected defaults\ngot:  %+v\nwant: %+v", cfg, want)
	}
}

// TestLoad_CorruptFile_ReturnsError verifies that Load on a non-JSON file
// returns an error rather than silently returning defaults.
func TestLoad_CorruptFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := os.WriteFile(path, []byte("this is not json {{{"), 0644); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err := config.Load(dir)
	if err == nil {
		t.Fatal("expected error loading corrupt config file, got nil")
	}
}

// TestLoad_PartialFile_FillsDefaults verifies that when config.json contains
// only some fields, the unset fields are filled with built-in defaults.
func TestLoad_PartialFile_FillsDefaults(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantCfg  config.Config
	}{
		{
			name: "only validity_days set — other fields default",
			json: `{"default_validity_days": 30}`,
			wantCfg: config.Config{
				CAOrg:               "Qala CA",
				CACNRoot:            "Qala Root CA",
				CACNIntermediate:    "Qala Intermediate CA",
				CertOrg:             "Qala Default OU",
				DefaultValidityDays: 30,
			},
		},
		{
			name: "only cert_org set — other fields default",
			json: `{"cert_org": "Custom OU"}`,
			wantCfg: config.Config{
				CAOrg:               "Qala CA",
				CACNRoot:            "Qala Root CA",
				CACNIntermediate:    "Qala Intermediate CA",
				CertOrg:             "Custom OU",
				DefaultValidityDays: 365,
			},
		},
		{
			name: "empty JSON object — all fields default",
			json: `{}`,
			wantCfg: config.Defaults(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")

			if err := os.WriteFile(path, []byte(tt.json), 0644); err != nil {
				t.Fatalf("write partial config: %v", err)
			}

			loaded, err := config.Load(dir)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if loaded != tt.wantCfg {
				t.Errorf("loaded config mismatch\ngot:  %+v\nwant: %+v", loaded, tt.wantCfg)
			}
		})
	}
}
