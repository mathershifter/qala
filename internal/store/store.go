package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
	_ "modernc.org/sqlite"
)

// Store persists certificate records in SQLite.
type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

// New opens (or creates) the SQLite database at dbPath, runs migrations, and
// returns a ready Store.
func New(dbPath string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite performs best with a single writer connection.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{db: db, logger: logger}, nil
}

// Save inserts an issued certificate record including the private key.
func (s *Store) Save(ctx context.Context, c cert.IssuedCert) error {
	const q = `
		INSERT INTO certificates (serial, type, common_name, certificate_pem, private_key_pem, issued_at, expires_at, revoked_at, revocation_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		c.Serial,
		string(c.Type),
		c.CommonName,
		c.CertificatePEM,
		c.PrivateKeyPEM,
		c.IssuedAt.UTC().Format(time.RFC3339),
		c.ExpiresAt.UTC().Format(time.RFC3339),
		c.RevokedAt,
		c.RevocationReason,
	)
	if err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}
	return nil
}

// List returns certificate summaries matching the filter.
func (s *Store) List(ctx context.Context, filter cert.ListFilter) ([]cert.Summary, error) {
	var args []any
	var where []string
	now := time.Now().UTC().Format(time.RFC3339)
	if filter.Type != nil {
		where = append(where, "type = ?")
		args = append(args, string(*filter.Type))
	}

	if !filter.Expired {
		where = append(where, "expires_at > ?")
		args = append(args, now)
	}

	if !filter.Revoked {
		where = append(where, "revoked_at IS NULL")
	}

	q := "SELECT serial, type, common_name, issued_at, expires_at, revoked_at, revocation_reason FROM certificates"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY issued_at DESC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	q += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var results []cert.Summary
	for rows.Next() {
		var summary cert.Summary
		var issuedStr, expiresStr string
		var revokedAt *time.Time
		var RevocationReason string
		var certType string

		if err := rows.Scan(&summary.Serial, &certType, &summary.CommonName, &issuedStr, &expiresStr, &revokedAt, &RevocationReason); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		summary.Type = cert.CertType(certType)

		summary.IssuedAt, err = time.Parse(time.RFC3339, issuedStr)
		if err != nil {
			return nil, fmt.Errorf("parse issued_at: %w", err)
		}
		summary.ExpiresAt, err = time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return nil, fmt.Errorf("parse expires_at: %w", err)
		}
		// summary.RevokedAt, err = time.Parse(time.RFC3339, revokedStr)
		// if err != nil {
		// 	return nil, fmt.Errorf("parse revoked_at: %w", err)
		// }

		results = append(results, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return results, nil
}

// Get retrieves a single certificate by serial, including the private key.
// Returns cert.ErrNotFound if the serial does not exist.
func (s *Store) Get(ctx context.Context, serial string) (cert.IssuedCert, error) {
	const q = `
		SELECT serial, type, common_name, certificate_pem, private_key_pem, issued_at, expires_at, revoked_at, revocation_reason
		FROM certificates WHERE serial = ?`

	return s.scanIssuedCert(s.db.QueryRowContext(ctx, q, serial), serial)
}

// GetActiveByCN retrieves the active (non-expired) certificate for a given
// type and common name. Returns cert.ErrNotFound if none exists.
func (s *Store) GetActiveByCN(ctx context.Context, certType cert.CertType, cn string) (cert.IssuedCert, error) {
	const q = `
		SELECT serial, type, common_name, certificate_pem, private_key_pem, issued_at, expires_at, revoked_at, revocation_reason
		FROM certificates
		WHERE type = ? AND common_name = ? AND expires_at > ?
		ORDER BY issued_at DESC
		LIMIT 1`

	return s.scanIssuedCert(
		s.db.QueryRowContext(ctx, q, string(certType), cn, time.Now().UTC().Format(time.RFC3339)),
		cn,
	)
}

// Delete removes a certificate record by serial. Returns cert.ErrNotFound if
// the serial does not exist.
func (s *Store) Delete(ctx context.Context, serial string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE serial = ?`, serial)
	if err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", cert.ErrNotFound, serial)
	}
	return nil
}

func (s *Store) ListRevoked(ctx context.Context) ([]cert.Summary, error) {
	return s.List(ctx, cert.ListFilter{
		Revoked: true,
		Expired: false,
	})
}

func (s *Store) Revoke(ctx context.Context, serial string, at time.Time, reason string) error {

	res, err := s.db.ExecContext(ctx, `UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE serial = ?`, at.Format(time.RFC3339), reason, serial)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", cert.ErrNotFound, serial)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) scanIssuedCert(row *sql.Row, notFoundKey string) (cert.IssuedCert, error) {
	var c cert.IssuedCert
	var issuedStr, expiresStr, certType string

	err := row.Scan(&c.Serial, &certType, &c.CommonName, &c.CertificatePEM, &c.PrivateKeyPEM, &issuedStr, &expiresStr, &c.RevokedAt, &c.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return cert.IssuedCert{}, fmt.Errorf("%w: %s", cert.ErrNotFound, notFoundKey)
	}
	if err != nil {
		return cert.IssuedCert{}, fmt.Errorf("get certificate: %w", err)
	}

	c.Type = cert.CertType(certType)

	c.IssuedAt, err = time.Parse(time.RFC3339, issuedStr)
	if err != nil {
		return cert.IssuedCert{}, fmt.Errorf("parse issued_at: %w", err)
	}
	c.ExpiresAt, err = time.Parse(time.RFC3339, expiresStr)
	if err != nil {
		return cert.IssuedCert{}, fmt.Errorf("parse expires_at: %w", err)
	}

	return c, nil
}

func migrate(db *sql.DB) error {
	// Create table if it doesn't exist.
	const ddl = `
	CREATE TABLE IF NOT EXISTS certificates (
		serial            STRING PRIMARY KEY,
		type              TEXT NOT NULL,
		common_name       TEXT NOT NULL,
		certificate_pem   TEXT NOT NULL,
		private_key_pem   TEXT NOT NULL DEFAULT '',
		issued_at         TEXT NOT NULL,
		expires_at        TEXT NOT NULL,
		revoked_at		  DATETIME DEFAULT NULL,
		revocation_reason TEXT NOT NULL DEFAULT ""
	);`

	if _, err := db.Exec(ddl); err != nil {
		return err
	}

	// Add private_key_pem column to databases created before it was introduced.
	if exists, err := columnExists(db, "certificates", "private_key_pem"); err != nil {
		return err
	} else if !exists {
		if _, err := db.Exec(`ALTER TABLE certificates ADD COLUMN private_key_pem TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add private_key_pem column: %w", err)
		}
	}

	return nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, colType, notnull, pk string
		var dfltValue *string // nullable
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}

	return false, rows.Err()
}
