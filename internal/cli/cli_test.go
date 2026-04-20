package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// ---------------------------------------------------------------------------
// envOrDefault
// ---------------------------------------------------------------------------

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envVal   string
		fallback string
		want     string
	}{
		{
			name:     "returns env var when set",
			key:      "QALA_TEST_KEY_ENVDEFAULT",
			envVal:   "from-env",
			fallback: "default",
			want:     "from-env",
		},
		{
			name:     "returns fallback when env var not set",
			key:      "QALA_TEST_KEY_ENVDEFAULT",
			envVal:   "",
			fallback: "fallback-value",
			want:     "fallback-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				t.Setenv(tt.key, tt.envVal)
			} else {
				os.Unsetenv(tt.key)
			}

			got := envOrDefault(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envOrDefault(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// writeFiles
// ---------------------------------------------------------------------------

func TestWriteFiles(t *testing.T) {
	tests := []struct {
		name     string
		certPEM  string
		keyPEM   string
		chainPEM string
	}{
		{
			name:     "writes all three files",
			certPEM:  "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
			keyPEM:   "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
			chainPEM: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
		},
		{
			name:     "empty PEM content still creates files",
			certPEM:  "",
			keyPEM:   "",
			chainPEM: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if err := writeFiles(dir, tt.certPEM, tt.keyPEM, tt.chainPEM); err != nil {
				t.Fatalf("writeFiles: %v", err)
			}

			// Check cert.pem
			certData, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
			if err != nil {
				t.Fatalf("read cert.pem: %v", err)
			}
			if string(certData) != tt.certPEM {
				t.Errorf("cert.pem: got %q, want %q", certData, tt.certPEM)
			}

			// Check key.pem
			keyData, err := os.ReadFile(filepath.Join(dir, "key.pem"))
			if err != nil {
				t.Fatalf("read key.pem: %v", err)
			}
			if string(keyData) != tt.keyPEM {
				t.Errorf("key.pem: got %q, want %q", keyData, tt.keyPEM)
			}

			// Check chain.pem
			chainData, err := os.ReadFile(filepath.Join(dir, "chain.pem"))
			if err != nil {
				t.Fatalf("read chain.pem: %v", err)
			}
			if string(chainData) != tt.chainPEM {
				t.Errorf("chain.pem: got %q, want %q", chainData, tt.chainPEM)
			}
		})
	}
}

func TestWriteFiles_CreatesOutputDir(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "nested", "subdir")

	// The directory does not exist yet; writeFiles should create it.
	if err := writeFiles(outDir, "cert", "key", "chain"); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}

	if _, err := os.Stat(outDir); err != nil {
		t.Errorf("expected output dir to exist: %v", err)
	}
}

// ---------------------------------------------------------------------------
// getJSON
// ---------------------------------------------------------------------------

func TestGetJSON_HappyPath(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}
	want := payload{Value: "hello"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	var got payload
	if err := getJSON(srv.URL+"/", &got); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if got.Value != want.Value {
		t.Errorf("Value: got %q, want %q", got.Value, want.Value)
	}
}

func TestGetJSON_ServerError_WithJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	var v any
	err := getJSON(srv.URL+"/", &v)
	if err == nil {
		t.Fatal("expected error from 404 response, got nil")
	}
}

func TestGetJSON_ServerError_WithoutJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var v any
	err := getJSON(srv.URL+"/", &v)
	if err == nil {
		t.Fatal("expected error from 500 response, got nil")
	}
}

func TestGetJSON_BadURL(t *testing.T) {
	var v any
	err := getJSON("http://127.0.0.1:0/impossible", &v)
	if err == nil {
		t.Fatal("expected error from unreachable URL, got nil")
	}
}

func TestGetJSON_InvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json {{{"))
	}))
	defer srv.Close()

	var v struct{ Value string }
	err := getJSON(srv.URL+"/", &v)
	if err == nil {
		t.Fatal("expected error decoding invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// postJSON
// ---------------------------------------------------------------------------

func TestPostJSON_HappyPath(t *testing.T) {
	type request struct {
		Name string `json:"name"`
	}
	type response struct {
		OK bool `json:"ok"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response{OK: true})
	}))
	defer srv.Close()

	var resp response
	if err := postJSON(srv.URL+"/", request{Name: "test"}, &resp); err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if !resp.OK {
		t.Error("expected OK=true in response")
	}
}

func TestPostJSON_ServerError_WithJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "already exists"})
	}))
	defer srv.Close()

	var v any
	err := postJSON(srv.URL+"/", struct{}{}, &v)
	if err == nil {
		t.Fatal("expected error from 409 response, got nil")
	}
}

func TestPostJSON_ServerError_WithoutJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	var v any
	err := postJSON(srv.URL+"/", struct{}{}, &v)
	if err == nil {
		t.Fatal("expected error from 400 response, got nil")
	}
}

func TestPostJSON_BadURL(t *testing.T) {
	var v any
	err := postJSON("http://127.0.0.1:0/impossible", struct{}{}, &v)
	if err == nil {
		t.Fatal("expected error from unreachable URL, got nil")
	}
}

func TestPostJSON_InvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{invalid"))
	}))
	defer srv.Close()

	var v struct{ Value string }
	err := postJSON(srv.URL+"/", struct{}{}, &v)
	if err == nil {
		t.Fatal("expected error decoding invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// serialFromConflict
// ---------------------------------------------------------------------------

func TestSerialFromConflict_HappyPath(t *testing.T) {
	wantSerial := "deadbeef"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"serial": wantSerial})
	}))
	defer srv.Close()

	serial, err := serialFromConflict(srv.URL+"/sign/server", struct{}{})
	if err != nil {
		t.Fatalf("serialFromConflict: %v", err)
	}
	if serial != wantSerial {
		t.Errorf("got serial %q, want %q", serial, wantSerial)
	}
}

func TestSerialFromConflict_Not409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := serialFromConflict(srv.URL+"/sign/server", struct{}{})
	if err == nil {
		t.Fatal("expected error when response is not 409, got nil")
	}
}

func TestSerialFromConflict_MissingSerial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "conflict"}) // no serial field
	}))
	defer srv.Close()

	_, err := serialFromConflict(srv.URL+"/sign/server", struct{}{})
	if err == nil {
		t.Fatal("expected error when serial is missing, got nil")
	}
}

func TestSerialFromConflict_BadURL(t *testing.T) {
	_, err := serialFromConflict("http://127.0.0.1:0/sign/server", struct{}{})
	if err == nil {
		t.Fatal("expected error from unreachable URL, got nil")
	}
}

// ---------------------------------------------------------------------------
// getIssuedCert
// ---------------------------------------------------------------------------

func TestGetIssuedCert_HappyPath(t *testing.T) {
	issued := cert.IssuedCert{
		Serial:     "abc123",
		CommonName: "svc.lab",
		Type:       cert.TypeServer,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issued)
	}))
	defer srv.Close()

	got, err := getIssuedCert(srv.URL, "server", "svc.lab")
	if err != nil {
		t.Fatalf("getIssuedCert: %v", err)
	}
	if got.Serial != issued.Serial {
		t.Errorf("Serial: got %q, want %q", got.Serial, issued.Serial)
	}
}

func TestGetIssuedCert_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	_, err := getIssuedCert(srv.URL, "server", "unknown.lab")
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
}

// ---------------------------------------------------------------------------
// buildLogger
// ---------------------------------------------------------------------------

func TestBuildLogger(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"debug level", "debug"},
		{"info level", "info"},
		{"warn level", "warn"},
		{"error level", "error"},
		{"unknown falls back to info", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &rootOptions{LogLevel: tt.logLevel}
			logger := buildLogger(opts)
			if logger == nil {
				t.Error("buildLogger returned nil")
			}
		})
	}
}
