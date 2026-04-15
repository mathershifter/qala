package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const configFile = "config.json"

// Config holds operational settings persisted at init time and read by serve.
type Config struct {
	// CA subject fields — used only at init time to set CA certificate subjects.
	CAOrg             string `json:"ca_org"`
	CACNRoot          string `json:"ca_cn_root"`
	CACNIntermediate  string `json:"ca_cn_intermediate"`

	// Leaf certificate defaults — applied to every issued certificate.
	CertOrg             string `json:"cert_org"`
	DefaultValidityDays int    `json:"default_validity_days"`
}

// Defaults returns a Config populated with the built-in default values.
func Defaults() Config {
	return Config{
		CAOrg:               "Qala CA",
		CACNRoot:            "Qala Root CA",
		CACNIntermediate:    "Qala Intermediate CA",
		CertOrg:             "Qala Default OU",
		DefaultValidityDays: 365,
	}
}

// Save writes cfg to <dataDir>/config.json.
func Save(dataDir string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, configFile), data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// Load reads <dataDir>/config.json. If the file does not exist, Defaults() is
// returned so callers work correctly against pre-config data dirs.
func Load(dataDir string) (Config, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, configFile))
	if os.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Defaults()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
