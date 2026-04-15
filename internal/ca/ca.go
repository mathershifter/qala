package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ErrAlreadyInitialized is returned by Init when CA files already exist.
var ErrAlreadyInitialized = errors.New("CA already initialized")

// CAConfig holds subject field configuration for the Root and Intermediate CAs.
// Empty fields are replaced with built-in defaults inside Init.
type CAConfig struct {
	RootCN         string
	IntermediateCN string
	Organization   string
}

// CA holds the loaded Intermediate and Root CA certificates and the
// Intermediate CA private key. The Root CA key is not kept in memory after
// the Intermediate CA is signed.
type CA struct {
	intermediateKey  *ecdsa.PrivateKey
	intermediateCert *x509.Certificate
	rootCert         *x509.Certificate
	crl              *x509.RevocationList
}

const (
	rootKeyFile  = "root-ca.key.pem"
	rootCertFile = "root-ca.cert.pem"
	intKeyFile   = "intermediate-ca.key.pem"
	intCertFile  = "intermediate-ca.cert.pem"
)

// Init generates the Root CA and Intermediate CA and writes PEM files to
// dataDir. Returns ErrAlreadyInitialized if any CA file already exists.
// Empty CAConfig fields are replaced with built-in defaults.
func Init(dataDir string, cfg CAConfig, logger *slog.Logger) error {
	if cfg.RootCN == "" {
		cfg.RootCN = "Qala Root CA"
	}
	if cfg.IntermediateCN == "" {
		cfg.IntermediateCN = "Qala Intermediate CA"
	}
	if cfg.Organization == "" {
		cfg.Organization = "Qala CA"
	}
	for _, name := range []string{rootKeyFile, rootCertFile, intKeyFile, intCertFile} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err == nil {
			return fmt.Errorf("%w: %s exists", ErrAlreadyInitialized, name)
		}
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	logger.Info("generating root CA key")
	rootKey, err := generateECKey(elliptic.P384())
	if err != nil {
		return fmt.Errorf("generate root CA key: %w", err)
	}

	rootSerial, err := newSerial()
	if err != nil {
		return fmt.Errorf("generate root serial: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   cfg.RootCN,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fmt.Errorf("parse root certificate: %w", err)
	}

	logger.Info("generating intermediate CA key")
	intKey, err := generateECKey(elliptic.P384())
	if err != nil {
		return fmt.Errorf("generate intermediate CA key: %w", err)
	}

	intSerial, err := newSerial()
	if err != nil {
		return fmt.Errorf("generate intermediate serial: %w", err)
	}

	intTemplate := &x509.Certificate{
		SerialNumber: intSerial,
		Subject: pkix.Name{
			CommonName:   cfg.IntermediateCN,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create intermediate certificate: %w", err)
	}

	// crl, err := ca.initCRL()
	// if err != nil {
	// 	return fmt.Errorf("failed to initialize CRL: %w", err)
	// }

	if err := writeKeyFile(filepath.Join(dataDir, rootKeyFile), rootKey); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}
	if err := writeCertFile(filepath.Join(dataDir, rootCertFile), rootDER); err != nil {
		return fmt.Errorf("write root cert: %w", err)
	}
	if err := writeKeyFile(filepath.Join(dataDir, intKeyFile), intKey); err != nil {
		return fmt.Errorf("write intermediate key: %w", err)
	}
	if err := writeCertFile(filepath.Join(dataDir, intCertFile), intDER); err != nil {
		return fmt.Errorf("write intermediate cert: %w", err)
	}
	// if err := writeCRLFile(filepath.Join(dataDir, crlFile), crl); err != nil {
	// 	return fmt.Errorf("write CRL: %w", err)
	// }

	logger.Info("CA initialized", "data_dir", dataDir)

	return nil
}

// Load reads the Intermediate CA key and both CA certificates from dataDir
// and returns a CA ready to sign leaf certificates.
func LoadCA(dataDir string, logger *slog.Logger) (*CA, error) {
	intKey, err := loadECKey(filepath.Join(dataDir, intKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load intermediate key: %w", err)
	}

	intCert, err := loadCert(filepath.Join(dataDir, intCertFile))
	if err != nil {
		return nil, fmt.Errorf("load intermediate cert: %w", err)
	}

	rootCert, err := loadCert(filepath.Join(dataDir, rootCertFile))
	if err != nil {
		return nil, fmt.Errorf("load root cert: %w", err)
	}

	logger.Info("CA loaded", "data_dir", dataDir)
	return &CA{
		intermediateKey:  intKey,
		intermediateCert: intCert,
		rootCert:         rootCert,
	}, nil
}

// Sign signs a leaf certificate template with the Intermediate CA key.
// The caller provides the template and the leaf public key.
func (c *CA) Sign(template *x509.Certificate, pub any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, c.intermediateCert, pub, c.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	return cert, nil
}

func (c *CA) SignCRL(template *x509.RevocationList) (*x509.RevocationList, error) {
	der, err := x509.CreateRevocationList(rand.Reader, template, c.intermediateCert, c.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("sign revocation list: %w", err)
	}

	return x509.ParseRevocationList(der)
}

func (c *CA) CheckSignatureWith(fn func(*x509.Certificate) error) error {
	return fn(c.intermediateCert)
}

func (c *CA) Signed(cert *x509.Certificate) bool {
	if err := cert.CheckSignatureFrom(c.intermediateCert); err != nil {
		return false
	}
	return true
}

// CertPEM returns the DER-encoded certificate as a PEM string.
func (c *CA) CertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// ChainPEM returns the PEM bundle: Intermediate CA cert followed by Root CA cert.
func (c *CA) ChainPEM() string {
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.intermediateCert.Raw})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootCert.Raw})
	return string(intPEM) + string(rootPEM)
}

// --- internal helpers ---

func generateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func writeKeyFile(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(path, der, "PRIVATE KEY")
}

func writeCertFile(path string, der []byte) error {
	return writePEMFile(path, der, "CERTIFICATE")
}

func writeCRLFile(path string, der []byte) error {
	return writePEMFile(path, der, "X509 CRL")
}

func writePEMFile(path string, der []byte, kind string) error {
	block := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	return os.WriteFile(path, block, 0644)
}

func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA key in %s", path)
	}

	return ecKey, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	return x509.ParseCertificate(block.Bytes)
}
