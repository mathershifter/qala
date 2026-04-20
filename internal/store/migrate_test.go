package store_test

import (
	"path/filepath"
	"testing"

	"gitlab.aristanetworks.com/jmather/qala/internal/store"
)

// newTestStoreAt opens a store at path and returns (nil, err) on failure
// rather than calling t.Fatal, so callers can check the error themselves.
func newTestStoreAt(t *testing.T, path string) (*store.Store, error) {
	t.Helper()
	return store.New(path, testLogger())
}

// newTestStoreAtPath opens a store at path, fatally failing if it errors.
func newTestStoreAtPath(t *testing.T, path string) (*store.Store, error) {
	t.Helper()
	return store.New(path, testLogger())
}

// TestNew_InvalidPath verifies that New returns an error when the database
// path cannot be opened (e.g. a directory that does not exist).
func TestNew_InvalidPath(t *testing.T) {
	// Use a path inside a non-existent directory — SQLite open will fail.
	_, err := newTestStoreAt(t, "/nonexistent/dir/that/cannot/exist/test.db")
	if err == nil {
		t.Fatal("expected error opening DB at invalid path, got nil")
	}
}

// TestNew_MigrationIdempotent verifies that calling New twice on the same DB
// file (and thus running migrate twice) succeeds without error.
func TestNew_MigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s1, err := newTestStoreAtPath(t, dbPath)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	s1.Close()

	// Second open should re-run migrate without error.
	s2, err := newTestStoreAtPath(t, dbPath)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	s2.Close()
}
