package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/ca"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestInit(t *testing.T) {
	t.Run("happy path creates parseable CA files", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.LoadCA(dir, testLogger())
		if err != nil {
			t.Fatalf("Load after Init: %v", err)
		}

		chain := loaded.ChainPEM()
		if chain == "" {
			t.Fatal("ChainPEM returned empty string")
		}

		// Verify both certs in the chain parse.
		rest := []byte(chain)
		var certs []*x509.Certificate
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse cert from chain: %v", err)
			}
			certs = append(certs, c)
		}

		if len(certs) != 2 {
			t.Fatalf("expected 2 certs in chain, got %d", len(certs))
		}
	})

	t.Run("double init returns error", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
			t.Fatalf("first Init: %v", err)
		}

		if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err == nil {
			t.Fatal("expected error on second Init, got nil")
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("loads CA files written by Init", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.LoadCA(dir, testLogger())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if loaded == nil {
			t.Fatal("Load returned nil CA")
		}

		if loaded.ChainPEM() == "" {
			t.Fatal("ChainPEM empty after Load")
		}
	})

	t.Run("missing files returns error", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ca.LoadCA(dir, testLogger())
		if err == nil {
			t.Fatal("expected error loading from empty dir, got nil")
		}
	})
}

// TestInit_CAConfigDefaults verifies that Init with an empty CAConfig uses the
// built-in defaults for Root CN, Intermediate CN, and Organization, as
// specified in SPEC.md §10.2 and §4.
func TestInit_CAConfigDefaults(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ca.CAConfig
		wantRoot string
		wantInt  string
		wantOrg  string
	}{
		{
			name:     "empty CAConfig uses all built-in defaults",
			cfg:      ca.CAConfig{},
			wantRoot: "Qala Root CA",
			wantInt:  "Qala Intermediate CA",
			wantOrg:  "Qala CA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := ca.Init(dir, tt.cfg, testLogger()); err != nil {
				t.Fatalf("Init: %v", err)
			}

			loaded, err := ca.LoadCA(dir, testLogger())
			if err != nil {
				t.Fatalf("LoadCA: %v", err)
			}

			// Parse both certs from the chain to inspect their subjects.
			rest := []byte(loaded.ChainPEM())
			var certs []*x509.Certificate
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("parse cert from chain: %v", err)
				}
				certs = append(certs, c)
			}

			if len(certs) != 2 {
				t.Fatalf("expected 2 certs in chain, got %d", len(certs))
			}

			// Chain order: intermediate first, root second.
			intCert := certs[0]
			rootCert := certs[1]

			if intCert.Subject.CommonName != tt.wantInt {
				t.Errorf("intermediate CN: got %q, want %q", intCert.Subject.CommonName, tt.wantInt)
			}
			if rootCert.Subject.CommonName != tt.wantRoot {
				t.Errorf("root CN: got %q, want %q", rootCert.Subject.CommonName, tt.wantRoot)
			}
			if len(intCert.Subject.Organization) == 0 || intCert.Subject.Organization[0] != tt.wantOrg {
				t.Errorf("intermediate Org: got %v, want [%q]", intCert.Subject.Organization, tt.wantOrg)
			}
			if len(rootCert.Subject.Organization) == 0 || rootCert.Subject.Organization[0] != tt.wantOrg {
				t.Errorf("root Org: got %v, want [%q]", rootCert.Subject.Organization, tt.wantOrg)
			}
		})
	}
}

// TestInit_CAConfigCustom verifies that Init with custom CAConfig values uses
// those values in the generated CA certificate subjects.
func TestInit_CAConfigCustom(t *testing.T) {
	tests := []struct {
		name string
		cfg  ca.CAConfig
	}{
		{
			name: "custom root CN, intermediate CN, and org",
			cfg: ca.CAConfig{
				RootCN:         "My Root CA",
				IntermediateCN: "My Intermediate CA",
				Organization:   "My Org",
			},
		},
		{
			name: "partial override — only org",
			cfg: ca.CAConfig{
				Organization: "Partial Org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := ca.Init(dir, tt.cfg, testLogger()); err != nil {
				t.Fatalf("Init: %v", err)
			}

			loaded, err := ca.LoadCA(dir, testLogger())
			if err != nil {
				t.Fatalf("LoadCA: %v", err)
			}

			rest := []byte(loaded.ChainPEM())
			var certs []*x509.Certificate
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("parse cert: %v", err)
				}
				certs = append(certs, c)
			}

			if len(certs) != 2 {
				t.Fatalf("expected 2 certs in chain, got %d", len(certs))
			}

			intCert := certs[0]
			rootCert := certs[1]

			// Determine expected values — empty fields fall back to built-ins.
			wantRootCN := tt.cfg.RootCN
			if wantRootCN == "" {
				wantRootCN = "Qala Root CA"
			}
			wantIntCN := tt.cfg.IntermediateCN
			if wantIntCN == "" {
				wantIntCN = "Qala Intermediate CA"
			}
			wantOrg := tt.cfg.Organization
			if wantOrg == "" {
				wantOrg = "Qala CA"
			}

			if rootCert.Subject.CommonName != wantRootCN {
				t.Errorf("root CN: got %q, want %q", rootCert.Subject.CommonName, wantRootCN)
			}
			if intCert.Subject.CommonName != wantIntCN {
				t.Errorf("intermediate CN: got %q, want %q", intCert.Subject.CommonName, wantIntCN)
			}
			if len(rootCert.Subject.Organization) == 0 || rootCert.Subject.Organization[0] != wantOrg {
				t.Errorf("root Org: got %v, want [%q]", rootCert.Subject.Organization, wantOrg)
			}
			if len(intCert.Subject.Organization) == 0 || intCert.Subject.Organization[0] != wantOrg {
				t.Errorf("intermediate Org: got %v, want [%q]", intCert.Subject.Organization, wantOrg)
			}
		})
	}
}

func TestSign(t *testing.T) {
	t.Run("signed leaf verifies against CA chain", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.LoadCA(dir, testLogger())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate leaf key: %v", err)
		}

		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatalf("generate serial: %v", err)
		}

		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "test.lab"},
			DNSNames:              []string{"test.lab"},
			NotBefore:             time.Now().UTC(),
			NotAfter:              time.Now().UTC().Add(90 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		signed, err := loaded.Sign(template, &leafKey.PublicKey)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if signed.Subject.CommonName != "test.lab" {
			t.Errorf("CN: got %q, want %q", signed.Subject.CommonName, "test.lab")
		}

		if len(signed.DNSNames) != 1 || signed.DNSNames[0] != "test.lab" {
			t.Errorf("DNSNames: got %v", signed.DNSNames)
		}
	})
}
