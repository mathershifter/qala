package crl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
	"gitlab.aristanetworks.com/jmather/qala/internal/crl"
)

// --- fakes ---

type fakeSigner struct {
	signFn   func(template *x509.Certificate, pub any) (*x509.Certificate, error)
	chainPEM string
}

func (f *fakeSigner) Sign(template *x509.Certificate, pub any) (*x509.Certificate, error) {
	return f.signFn(template, pub)
}

func (f *fakeSigner) ChainPEM() string { return f.chainPEM }

type fakeStore struct {
	saved       []cert.IssuedCert
	listFilter  cert.ListFilter
	listResults []cert.Summary
}

func (f *fakeStore) Save(_ context.Context, c cert.IssuedCert) error {
	f.saved = append(f.saved, c)
	return nil
}

func (f *fakeStore) List(_ context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
	f.listFilter = filter
	return f.listResults, nil
}

func (f *fakeStore) Get(_ context.Context, serial string) (cert.IssuedCert, error) {
	for _, c := range f.saved {
		if c.Serial == serial {
			return c, nil
		}
	}
	return cert.IssuedCert{}, cert.ErrNotFound
}

func (f *fakeStore) GetActiveByCN(_ context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error) {
	now := time.Now()
	for _, c := range f.saved {
		if c.Type == certType && c.CommonName == cn && c.ExpiresAt.After(now) {
			return c, nil
		}
	}
	return cert.IssuedCert{}, cert.ErrNotFound
}

func (f *fakeStore) Delete(_ context.Context, serial string) error {
	for i, c := range f.saved {
		if c.Serial == serial {
			f.saved = append(f.saved[:i], f.saved[i+1:]...)
			return nil
		}
	}
	return cert.ErrNotFound
}

func (f *fakeStore) Revoke(_ context.Context, serial string, revokedAt time.Time, reason string) error {
	for i, c := range f.saved {
		if c.Serial == serial {
			c.RevokedAt = new(time.Now().UTC())
			c.RevocationReason = reason
			f.saved[i] = c
			return nil
		}
	}
	return cert.ErrNotFound
}

func (f *fakeStore) ListRevoked(ctx context.Context) ([]cert.Summary, error) {

	return f.List(ctx, cert.ListFilter{
		Revoked: true,
	})
}

// realSigner builds a minimal self-signed CA and uses it to sign leaf certs.
// This exercises the PEM encoding paths in the service.
type realSigner struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newRealSigner(t *testing.T) *realSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(der)
	return &realSigner{key: key, cert: caCert}
}

func (r *realSigner) SignCRL(template *x509.RevocationList) (*x509.RevocationList, error) {
	der, err := x509.CreateRevocationList(rand.Reader, template, r.cert, r.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}
func (r *realSigner) CheckSignatureWith(fn func(*x509.Certificate) error) error {
	return fn(r.cert)
}

func TestLoadCRL(t *testing.T) {
	t.Run("loads CRL file written by Init", func(t *testing.T) {
		dir := t.TempDir()
		signer := newRealSigner(t)

		crl, err := crl.LoadOrInitCRL(dir, signer)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if crl.CurrentCRL() == nil {
			t.Fatal("Load returned nil CA")
		}

		// if crl.crl.Raw == nil {
		// 	t.Fatal("Issuer empty after Load")
		// }
	})
}

func TestRevoke(t *testing.T) {
	t.Run("revoke crl", func(t *testing.T) {
		dir := t.TempDir()
		signer := newRealSigner(t)

		crl, err := crl.LoadOrInitCRL(dir, signer)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		crl.Revoke(big.NewInt(1001).String(), time.Now().UTC(), "unspecified")
		crl.Revoke(big.NewInt(1002).String(), time.Now().UTC(), "unspecified")

		if err := crl.Check(); err != nil {
			t.Error(err)
		}
		if len(crl.List()) != 2 {
			t.Errorf("wrong crl length")
		}
	})
}

// TestRevoke_HexSerial verifies that Revoke succeeds when given a valid
// hex-encoded certificate serial string, as produced by the cert service.
func TestRevoke_HexSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial string
	}{
		{name: "lowercase hex", serial: "a1b2c3d4"},
		{name: "uppercase hex digits 0-9 only", serial: "0011223344"},
		{name: "mixed hex a-f", serial: "deadbeef"},
		{name: "single digit hex", serial: "f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			signer := newRealSigner(t)

			svc, err := crl.LoadOrInitCRL(dir, signer)
			if err != nil {
				t.Fatalf("LoadOrInitCRL: %v", err)
			}

			if err := svc.Revoke(tt.serial, time.Now().UTC(), "unspecified"); err != nil {
				t.Errorf("Revoke(%q): unexpected error: %v", tt.serial, err)
			}

			entries := svc.List()
			if len(entries) != 1 {
				t.Errorf("expected 1 CRL entry, got %d", len(entries))
			}
		})
	}
}

// TestRevoke_InvalidSerial verifies that Revoke returns an error when given a
// serial string that cannot be parsed as hexadecimal.
func TestRevoke_InvalidSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial string
	}{
		{name: "non-hex letters", serial: "xyz"},
		{name: "contains space", serial: "ab cd"},
		{name: "decimal with non-hex letters g-z", serial: "1009gz"},
		{name: "empty string", serial: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			signer := newRealSigner(t)

			svc, err := crl.LoadOrInitCRL(dir, signer)
			if err != nil {
				t.Fatalf("LoadOrInitCRL: %v", err)
			}

			err = svc.Revoke(tt.serial, time.Now().UTC(), "unspecified")
			if err == nil {
				t.Errorf("Revoke(%q): expected error for invalid hex serial, got nil", tt.serial)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RevocationReason.String()
// ---------------------------------------------------------------------------

func TestRevocationReasonString(t *testing.T) {
	tests := []struct {
		reason crl.RevocationReason
		want   string
	}{
		{crl.ReasonUnspecified, "unspecified"},
		{crl.ReasonKeyCompromise, "keyCompromise"},
		{crl.ReasonAffiliationChanged, "affiliationChanged"},
		{crl.ReasonSuperseded, "superseded"},
		{crl.ReasonCessationOfOperation, "cessationOfOperation"},
		{crl.ReasonCertificateHold, "certificateHold"},
		// Unknown value falls through to default.
		{crl.RevocationReason(99), "unspecified"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.reason.String()
			if got != tt.want {
				t.Errorf("RevocationReason(%d).String() = %q, want %q", int(tt.reason), got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ReasonFromStr — all spec-defined values
// ---------------------------------------------------------------------------

func TestReasonFromStr(t *testing.T) {
	tests := []struct {
		input string
		want  crl.RevocationReason
	}{
		{"keyCompromise", crl.ReasonKeyCompromise},
		{"affiliationChanged", crl.ReasonAffiliationChanged},
		{"superseded", crl.ReasonSuperseded},
		{"cessationOfOperation", crl.ReasonCessationOfOperation},
		{"certificateHold", crl.ReasonCertificateHold},
		// Unknown / empty strings map to unspecified.
		{"unspecified", crl.ReasonUnspecified},
		{"", crl.ReasonUnspecified},
		{"bogus", crl.ReasonUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.input+"->"+tt.want.String(), func(t *testing.T) {
			got := crl.ReasonFromStr(tt.input)
			if got != tt.want {
				t.Errorf("ReasonFromStr(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CurrentCRL when CRL exists (raw bytes returned)
// ---------------------------------------------------------------------------

func TestCurrentCRL_NonEmpty(t *testing.T) {
	dir := t.TempDir()
	signer := newRealSigner(t)

	svc, err := crl.LoadOrInitCRL(dir, signer)
	if err != nil {
		t.Fatalf("LoadOrInitCRL: %v", err)
	}

	der := svc.CurrentCRL()
	if len(der) == 0 {
		t.Error("expected non-empty DER bytes from CurrentCRL after init")
	}
}

// ---------------------------------------------------------------------------
// List when CRL is populated
// ---------------------------------------------------------------------------

func TestList_AfterRevocations(t *testing.T) {
	dir := t.TempDir()
	signer := newRealSigner(t)

	svc, err := crl.LoadOrInitCRL(dir, signer)
	if err != nil {
		t.Fatalf("LoadOrInitCRL: %v", err)
	}

	// Initially empty.
	if entries := svc.List(); len(entries) != 0 {
		t.Errorf("expected 0 entries before any revocations, got %d", len(entries))
	}

	// Add two revocations.
	if err := svc.Revoke("aabb", time.Now().UTC(), "keyCompromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := svc.Revoke("ccdd", time.Now().UTC(), "superseded"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	entries := svc.List()
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// LoadOrInitCRL — loads a pre-existing PEM file written to disk
// ---------------------------------------------------------------------------

func TestLoadOrInitCRL_LoadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	signer := newRealSigner(t)

	// First call creates and saves the CRL.
	svc1, err := crl.LoadOrInitCRL(dir, signer)
	if err != nil {
		t.Fatalf("first LoadOrInitCRL: %v", err)
	}
	// Revoke something so the CRL on disk has content.
	if err := svc1.Revoke("beef01", time.Now().UTC(), "unspecified"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Second call should load from the PEM file on disk.
	svc2, err := crl.LoadOrInitCRL(dir, signer)
	if err != nil {
		t.Fatalf("second LoadOrInitCRL: %v", err)
	}

	// The revoked entry should be present in the reloaded CRL.
	entries := svc2.List()
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after reload, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// read — malformed PEM file
// ---------------------------------------------------------------------------

func TestLoadOrInitCRL_BadPEMFile_FallsBackToNew(t *testing.T) {
	dir := t.TempDir()
	signer := newRealSigner(t)

	// Write garbage into crl.pem; LoadOrInitCRL should fall back to a new CRL.
	crlPath := filepath.Join(dir, "crl.pem")
	if err := os.WriteFile(crlPath, []byte("not-valid-pem"), 0644); err != nil {
		t.Fatalf("write bad pem: %v", err)
	}

	// This should not fail — it should create a new CRL when reading fails.
	svc, err := crl.LoadOrInitCRL(dir, signer)
	if err != nil {
		t.Fatalf("LoadOrInitCRL with bad PEM: %v", err)
	}

	if svc.CurrentCRL() == nil {
		t.Error("expected non-nil CRL after fallback init")
	}
}
