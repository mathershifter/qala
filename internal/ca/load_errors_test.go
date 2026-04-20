package ca_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.aristanetworks.com/jmather/qala/internal/ca"
)

// TestLoadCA_MissingIntermediateKey verifies that LoadCA returns an error
// when the intermediate CA key file is absent.
func TestLoadCA_MissingIntermediateKey(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Remove the intermediate key file.
	if err := os.Remove(filepath.Join(dir, "intermediate-ca.key.pem")); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	_, err := ca.LoadCA(dir, testLogger())
	if err == nil {
		t.Fatal("expected error loading CA with missing intermediate key, got nil")
	}
}

// TestLoadCA_MissingIntermediateCert verifies that LoadCA returns an error
// when the intermediate CA cert file is absent.
func TestLoadCA_MissingIntermediateCert(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Remove the intermediate cert file.
	if err := os.Remove(filepath.Join(dir, "intermediate-ca.cert.pem")); err != nil {
		t.Fatalf("remove cert: %v", err)
	}

	_, err := ca.LoadCA(dir, testLogger())
	if err == nil {
		t.Fatal("expected error loading CA with missing intermediate cert, got nil")
	}
}

// TestLoadCA_MissingRootCert verifies that LoadCA returns an error when the
// root CA cert file is absent.
func TestLoadCA_MissingRootCert(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Remove the root cert file.
	if err := os.Remove(filepath.Join(dir, "root-ca.cert.pem")); err != nil {
		t.Fatalf("remove cert: %v", err)
	}

	_, err := ca.LoadCA(dir, testLogger())
	if err == nil {
		t.Fatal("expected error loading CA with missing root cert, got nil")
	}
}

// TestLoadCA_CorruptKeyFile verifies that LoadCA returns an error when the
// intermediate key file contains invalid data (no PEM block).
func TestLoadCA_CorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Overwrite the intermediate key file with garbage.
	if err := os.WriteFile(filepath.Join(dir, "intermediate-ca.key.pem"), []byte("not-pem"), 0644); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}

	_, err := ca.LoadCA(dir, testLogger())
	if err == nil {
		t.Fatal("expected error loading CA with corrupt key file, got nil")
	}
}

// TestLoadCA_CorruptCertFile verifies that LoadCA returns an error when the
// intermediate cert file contains invalid data (no PEM block).
func TestLoadCA_CorruptCertFile(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, ca.CAConfig{}, testLogger()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Overwrite the intermediate cert file with garbage.
	if err := os.WriteFile(filepath.Join(dir, "intermediate-ca.cert.pem"), []byte("not-pem"), 0644); err != nil {
		t.Fatalf("write corrupt cert: %v", err)
	}

	_, err := ca.LoadCA(dir, testLogger())
	if err == nil {
		t.Fatal("expected error loading CA with corrupt cert file, got nil")
	}
}
