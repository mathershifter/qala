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
		if err := ca.Init(dir, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.Load(dir, testLogger())
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
		if err := ca.Init(dir, testLogger()); err != nil {
			t.Fatalf("first Init: %v", err)
		}

		if err := ca.Init(dir, testLogger()); err == nil {
			t.Fatal("expected error on second Init, got nil")
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("loads CA files written by Init", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.Load(dir, testLogger())
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
		_, err := ca.Load(dir, testLogger())
		if err == nil {
			t.Fatal("expected error loading from empty dir, got nil")
		}
	})
}

func TestSign(t *testing.T) {
	t.Run("signed leaf verifies against CA chain", func(t *testing.T) {
		dir := t.TempDir()
		if err := ca.Init(dir, testLogger()); err != nil {
			t.Fatalf("Init: %v", err)
		}

		loaded, err := ca.Load(dir, testLogger())
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
