package cert

import "time"

// KeyAlgorithm identifies the key algorithm for a certificate.
type KeyAlgorithm string

const (
	AlgorithmECDSA KeyAlgorithm = "ecdsa"
	AlgorithmRSA   KeyAlgorithm = "rsa"
)

// CertType distinguishes server from client certificates.
type CertType string

const (
	TypeServer CertType = "server"
	TypeClient CertType = "client"
)

// ServerRequest carries the parameters for issuing a TLS server certificate.
type ServerRequest struct {
	CommonName   string       `json:"common_name"`
	DNSNames     []string     `json:"dns_names"`
	IPAddresses  []string     `json:"ip_addresses"`
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	ValidityDays int          `json:"validity_days"`
}

// ClientRequest carries the parameters for issuing a client auth certificate.
type ClientRequest struct {
	CommonName   string       `json:"common_name"`
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	ValidityDays int          `json:"validity_days"`
}

// IssuedCert is the result of a successful certificate issuance.
// PrivateKeyPEM is returned exactly once at issuance and is never persisted.
type IssuedCert struct {
	Serial         string    `json:"serial"`
	Type           CertType  `json:"type"`
	CommonName     string    `json:"common_name"`
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	ChainPEM       string    `json:"chain_pem"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Summary is the list-view projection of an issued certificate. No PEM fields.
type Summary struct {
	Serial     string    `json:"serial"`
	Type       CertType  `json:"type"`
	CommonName string    `json:"common_name"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ListFilter controls which certificates are returned by List.
type ListFilter struct {
	Type           *CertType
	IncludeExpired bool
	Limit          int
	Offset         int
}
