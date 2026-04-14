package crl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
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
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
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
