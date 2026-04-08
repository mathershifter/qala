package cert_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/cert"
)

// --- fakes ---

type fakeSigner struct {
	signFn    func(template *x509.Certificate, pub any) (*x509.Certificate, error)
	chainPEM  string
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
		KeyUsage:              x509.KeyUsageCertSign,
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

func (r *realSigner) Sign(template *x509.Certificate, pub any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, r.cert, pub, r.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (r *realSigner) ChainPEM() string { return "chain-pem" }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- tests ---

func TestIssueServer(t *testing.T) {
	tests := []struct {
		name    string
		req     cert.ServerRequest
		seed    []cert.IssuedCert // pre-populated store entries
		wantErr error
	}{
		{
			name: "valid with DNS SAN",
			req:  cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}},
		},
		{
			name: "valid with IP SAN",
			req:  cert.ServerRequest{CommonName: "svc.lab", IPAddresses: []string{"10.0.0.1"}},
		},
		{
			name: "valid with explicit ecdsa algorithm",
			req:  cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, KeyAlgorithm: cert.AlgorithmECDSA},
		},
		{
			name: "valid with rsa algorithm",
			req:  cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, KeyAlgorithm: cert.AlgorithmRSA},
		},
		{
			name: "valid with explicit validity",
			req:  cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, ValidityDays: 30},
		},
		{
			name:    "missing common name",
			req:     cert.ServerRequest{DNSNames: []string{"svc.lab"}},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name:    "missing SANs",
			req:     cert.ServerRequest{CommonName: "svc.lab"},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name:    "invalid algorithm",
			req:     cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, KeyAlgorithm: "dsa"},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name:    "validity too large",
			req:     cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, ValidityDays: 366},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name:    "validity zero is allowed (defaults to 90)",
			req:     cert.ServerRequest{CommonName: "svc.lab", DNSNames: []string{"svc.lab"}, ValidityDays: 0},
			wantErr: nil,
		},
		{
			name:    "invalid IP address",
			req:     cert.ServerRequest{CommonName: "svc.lab", IPAddresses: []string{"not-an-ip"}},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name: "duplicate CN returns ErrCNAlreadyActive",
			req:  cert.ServerRequest{CommonName: "exists.lab", DNSNames: []string{"exists.lab"}},
			seed: []cert.IssuedCert{{
				Serial:    "preexisting",
				Type:      cert.TypeServer,
				CommonName: "exists.lab",
				ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
			}},
			wantErr: cert.ErrCNAlreadyActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := newRealSigner(t)
			store := &fakeStore{saved: tt.seed}
			svc := cert.NewService(signer, store, testLogger())

			issued, err := svc.IssueServer(context.Background(), tt.req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want wrapping %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if issued.Serial == "" {
				t.Error("Serial is empty")
			}
			if issued.CertificatePEM == "" {
				t.Error("CertificatePEM is empty")
			}
			if issued.PrivateKeyPEM == "" {
				t.Error("PrivateKeyPEM is empty")
			}
			if issued.Type != cert.TypeServer {
				t.Errorf("Type: got %q, want %q", issued.Type, cert.TypeServer)
			}
			if len(store.saved) != 1 {
				t.Errorf("expected 1 saved cert, got %d", len(store.saved))
			}
		})
	}
}

func TestIssueClient(t *testing.T) {
	tests := []struct {
		name    string
		req     cert.ClientRequest
		seed    []cert.IssuedCert
		wantErr error
	}{
		{
			name: "valid request",
			req:  cert.ClientRequest{CommonName: "alice"},
		},
		{
			name:    "missing common name",
			req:     cert.ClientRequest{},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name:    "invalid algorithm",
			req:     cert.ClientRequest{CommonName: "alice", KeyAlgorithm: "bad"},
			wantErr: cert.ErrInvalidRequest,
		},
		{
			name: "duplicate CN returns ErrCNAlreadyActive",
			req:  cert.ClientRequest{CommonName: "alice"},
			seed: []cert.IssuedCert{{
				Serial:     "preexisting-client",
				Type:       cert.TypeClient,
				CommonName: "alice",
				ExpiresAt:  time.Now().Add(90 * 24 * time.Hour),
			}},
			wantErr: cert.ErrCNAlreadyActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := cert.NewService(newRealSigner(t), &fakeStore{saved: tt.seed}, testLogger())

			issued, err := svc.IssueClient(context.Background(), tt.req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got err %v, want wrapping %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if issued.Type != cert.TypeClient {
				t.Errorf("Type: got %q, want %q", issued.Type, cert.TypeClient)
			}
		})
	}
}

func TestList(t *testing.T) {
	t.Run("delegates filter to store and applies default limit", func(t *testing.T) {
		store := &fakeStore{listResults: []cert.Summary{{Serial: "abc", CommonName: "svc"}}}
		svc := cert.NewService(newRealSigner(t), store, testLogger())

		results, err := svc.List(context.Background(), cert.ListFilter{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if store.listFilter.Limit != 100 {
			t.Errorf("expected default Limit=100, got %d", store.listFilter.Limit)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}
	})
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name    string
		serial  string
		seed    bool
		wantErr error
	}{
		{
			name:   "deletes existing certificate",
			serial: "abc",
			seed:   true,
		},
		{
			name:    "returns ErrNotFound for unknown serial",
			serial:  "nope",
			wantErr: cert.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &fakeStore{}
			if tt.seed {
				st.saved = []cert.IssuedCert{{
					Serial:    tt.serial,
					Type:      cert.TypeServer,
					CommonName: "svc.lab",
					ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
				}}
			}
			svc := cert.NewService(newRealSigner(t), st, testLogger())

			err := svc.Delete(context.Background(), tt.serial)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("got %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if len(st.saved) != 0 {
				t.Error("expected saved to be empty after delete")
			}
		})
	}
}

func TestGet(t *testing.T) {
	t.Run("returns cert when found", func(t *testing.T) {
		st := &fakeStore{}
		signer := newRealSigner(t)
		svc := cert.NewService(signer, st, testLogger())

		// Issue one to populate the fake store.
		issued, err := svc.IssueServer(context.Background(), cert.ServerRequest{
			CommonName: "svc.lab",
			DNSNames:   []string{"svc.lab"},
		})
		if err != nil {
			t.Fatalf("IssueServer: %v", err)
		}

		got, err := svc.Get(context.Background(), issued.Serial)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Serial != issued.Serial {
			t.Errorf("Serial: got %q, want %q", got.Serial, issued.Serial)
		}
	})

	t.Run("returns ErrNotFound for unknown serial", func(t *testing.T) {
		svc := cert.NewService(newRealSigner(t), &fakeStore{}, testLogger())

		_, err := svc.Get(context.Background(), "nope")
		if !errors.Is(err, cert.ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}
