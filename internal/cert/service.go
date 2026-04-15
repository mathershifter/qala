package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"
)

// Signer is the interface the Service requires from the CA layer.
type Signer interface {
	Sign(template *x509.Certificate, pub any) (*x509.Certificate, error)
	ChainPEM() string
}

type Revoker interface {
	Revoke(serial string, revokedAt time.Time, reason string) error
}

// Store is the interface the Service requires from the persistence layer.
type Store interface {
	Save(ctx context.Context, c IssuedCert) error
	List(ctx context.Context, filter ListFilter) ([]Summary, error)
	Get(ctx context.Context, serial string) (IssuedCert, error)
	GetActiveByCN(ctx context.Context, certType CertType, cn string) (IssuedCert, error)
	Delete(ctx context.Context, serial string) error
	Revoke(ctx context.Context, serial string, revokedAt time.Time, reason string) error
	ListRevoked(ctx context.Context) ([]Summary, error)
}

// Service issues and retrieves certificates.
type Service struct {
	ca       Signer
	crl      Revoker
	store    Store
	defaults CertDefaults
	logger   *slog.Logger
}

// NewService constructs a Service.
func NewService(ca Signer, crl Revoker, store Store, defaults CertDefaults, logger *slog.Logger) *Service {
	return &Service{ca: ca, crl: crl, store: store, defaults: defaults, logger: logger}
}

// IssueServer validates the request, generates a key pair, signs a TLS server
// certificate, persists the record, and returns the issued certificate.
// Returns *CNConflictError (wrapping ErrCNAlreadyActive) if an active
// certificate already exists for the requested common name.
func (s *Service) IssueServer(ctx context.Context, req ServerRequest) (IssuedCert, error) {
	if err := validateServerRequest(req); err != nil {
		return IssuedCert{}, err
	}

	if existing, err := s.store.GetActiveByCN(ctx, TypeServer, req.CommonName); err == nil {
		return IssuedCert{}, &CNConflictError{CommonName: req.CommonName, Serial: existing.Serial}
	}

	req.ValidityDays = s.resolveValidityDays(req.ValidityDays)
	req.KeyAlgorithm = defaultAlgorithm(req.KeyAlgorithm)

	priv, pub, err := generateKeyPair(req.KeyAlgorithm)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("generate key pair: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return IssuedCert{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	subject := pkix.Name{CommonName: req.CommonName}
	if s.defaults.Organization != "" {
		subject.Organization = []string{s.defaults.Organization}
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, name := range req.DNSNames {
		template.DNSNames = append(template.DNSNames, name)
	}

	for _, ipStr := range req.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return IssuedCert{}, fmt.Errorf("%w: invalid IP address %q", ErrInvalidRequest, ipStr)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	signed, err := s.ca.Sign(template, pub)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("sign server certificate: %w", err)
	}

	certPEM := encodeCertPEM(signed)
	keyPEM, err := encodePrivateKey(priv)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("encode private key: %w", err)
	}

	serialHex := fmt.Sprintf("%x", signed.SerialNumber.Bytes())
	issued := IssuedCert{
		Serial:         serialHex,
		Type:           TypeServer,
		CommonName:     req.CommonName,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		ChainPEM:       s.ca.ChainPEM(),
		IssuedAt:       now,
		ExpiresAt:      signed.NotAfter,
	}

	if err := s.store.Save(ctx, issued); err != nil {
		return IssuedCert{}, fmt.Errorf("persist certificate: %w", err)
	}

	s.logger.Info("server certificate issued", "serial", serialHex, "cn", req.CommonName)
	return issued, nil
}

// IssueClient validates the request, generates a key pair, signs a client auth
// certificate, persists the record, and returns the issued certificate.
// Returns *CNConflictError (wrapping ErrCNAlreadyActive) if an active
// certificate already exists for the requested common name.
func (s *Service) IssueClient(ctx context.Context, req ClientRequest) (IssuedCert, error) {
	if err := validateClientRequest(req); err != nil {
		return IssuedCert{}, err
	}

	if existing, err := s.store.GetActiveByCN(ctx, TypeClient, req.CommonName); err == nil {
		return IssuedCert{}, &CNConflictError{CommonName: req.CommonName, Serial: existing.Serial}
	}

	req.ValidityDays = s.resolveValidityDays(req.ValidityDays)
	req.KeyAlgorithm = defaultAlgorithm(req.KeyAlgorithm)

	priv, pub, err := generateKeyPair(req.KeyAlgorithm)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("generate key pair: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return IssuedCert{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	subject := pkix.Name{CommonName: req.CommonName}
	if s.defaults.Organization != "" {
		subject.Organization = []string{s.defaults.Organization}
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(req.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	signed, err := s.ca.Sign(template, pub)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("sign client certificate: %w", err)
	}

	certPEM := encodeCertPEM(signed)
	keyPEM, err := encodePrivateKey(priv)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("encode private key: %w", err)
	}

	serialHex := fmt.Sprintf("%x", signed.SerialNumber.Bytes())
	issued := IssuedCert{
		Serial:         serialHex,
		Type:           TypeClient,
		CommonName:     req.CommonName,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		ChainPEM:       s.ca.ChainPEM(),
		IssuedAt:       now,
		ExpiresAt:      signed.NotAfter,
	}

	if err := s.store.Save(ctx, issued); err != nil {
		return IssuedCert{}, fmt.Errorf("persist certificate: %w", err)
	}

	s.logger.Info("client certificate issued", "serial", serialHex, "cn", req.CommonName)
	return issued, nil
}

// List returns certificate summaries matching the filter.
func (s *Service) List(ctx context.Context, filter ListFilter) ([]Summary, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	return s.store.List(ctx, filter)
}

// Get returns a single issued certificate by serial.
func (s *Service) Get(ctx context.Context, serial string) (IssuedCert, error) {
	return s.store.Get(ctx, serial)
}

// GetByCN returns the active certificate for a given type and common name.
func (s *Service) GetByCN(ctx context.Context, certType CertType, cn string) (IssuedCert, error) {
	return s.store.GetActiveByCN(ctx, certType, cn)
}

// Delete removes a certificate record by serial.
func (s *Service) Delete(ctx context.Context, serial string) error {
	if err := s.store.Delete(ctx, serial); err != nil {
		return err
	}
	s.logger.Info("certificate deleted", "serial", serial)
	return nil
}

func (s *Service) Revoke(ctx context.Context, serial string, reason string) (Summary, error) {
	revokedAt := time.Now().UTC()
	if err := s.store.Revoke(ctx, serial, revokedAt, reason); err != nil {
		return Summary{}, err
	}
	if err := s.crl.Revoke(serial, revokedAt, reason); err != nil {
		return Summary{}, fmt.Errorf("update CRL: %w", err)
	}
	s.logger.Info("certificate revoked", "serial", serial)
	return Summary{
		Serial:           serial,
		RevokedAt:        revokedAt,
		RevocationReason: reason,
	}, nil
}

// --- internal helpers ---

func validateServerRequest(req ServerRequest) error {
	if req.CommonName == "" {
		return fmt.Errorf("%w: common_name is required", ErrInvalidRequest)
	}
	if len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return fmt.Errorf("%w: at least one dns_name or ip_address is required", ErrInvalidRequest)
	}
	if err := validateAlgorithm(req.KeyAlgorithm); err != nil {
		return err
	}
	if err := validateValidity(req.ValidityDays); err != nil {
		return err
	}
	return nil
}

func validateClientRequest(req ClientRequest) error {
	if req.CommonName == "" {
		return fmt.Errorf("%w: common_name is required", ErrInvalidRequest)
	}
	if err := validateAlgorithm(req.KeyAlgorithm); err != nil {
		return err
	}
	if err := validateValidity(req.ValidityDays); err != nil {
		return err
	}
	return nil
}

func validateAlgorithm(alg KeyAlgorithm) error {
	if alg == "" {
		return nil // will be defaulted
	}
	switch alg {
	case AlgorithmECDSA, AlgorithmRSA:
		return nil
	default:
		return fmt.Errorf("%w: unknown key_algorithm %q (must be \"ecdsa\" or \"rsa\")", ErrInvalidRequest, alg)
	}
}

func validateValidity(days int) error {
	if days == 0 {
		return nil // will be defaulted
	}
	if days < 1 || days > 365 {
		return fmt.Errorf("%w: validity_days must be between 1 and 365", ErrInvalidRequest)
	}
	return nil
}

// resolveValidityDays applies the per-request value, then the service default, then 365.
func (s *Service) resolveValidityDays(days int) int {
	if days != 0 {
		return days
	}
	if s.defaults.ValidityDays > 0 {
		return s.defaults.ValidityDays
	}
	return 365
}

func defaultAlgorithm(alg KeyAlgorithm) KeyAlgorithm {
	if alg == "" {
		return AlgorithmECDSA
	}
	return alg
}

func generateKeyPair(alg KeyAlgorithm) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch alg {
	case AlgorithmRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	default: // AlgorithmECDSA
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil
	}
}

func encodePrivateKey(key crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}
