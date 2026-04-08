package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
)

// rootOptions holds flags shared across all subcommands.
type rootOptions struct {
	DataDir  string
	LogLevel string
	APIURL   string
}

// Execute is the single exported entry point. Called from main.
func Execute() {
	opts := &rootOptions{}
	root := newRootCmd(opts)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "qala",
		Short: "Certificate signing service for lab environments",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Validate log level here so subcommands can rely on it being correct.
			switch opts.LogLevel {
			case "debug", "info", "warn", "error":
				return nil
			default:
				return fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", opts.LogLevel)
			}
		},
	}

	cmd.PersistentFlags().StringVar(&opts.DataDir, "data-dir",
		envOrDefault("QALA_DATA_DIR", "./data"), "path to CA keys, certs, and database")
	cmd.PersistentFlags().StringVar(&opts.LogLevel, "log-level",
		envOrDefault("QALA_LOG_LEVEL", "info"), "log level: debug, info, warn, error")
	cmd.PersistentFlags().StringVar(&opts.APIURL, "api-url",
		envOrDefault("QALA_API_URL", "http://localhost:8080"), "qala server URL (for client commands)")

	cmd.AddCommand(
		newInitCmd(opts),
		newServeCmd(opts),
		newSignCmd(opts),
		newListCmd(opts),
		newGetCmd(opts),
		newDeleteCmd(opts),
		newCAChainCmd(opts),
	)

	return cmd
}

func buildLogger(opts *rootOptions) *slog.Logger {
	var level slog.Level
	switch opts.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getJSON sends a GET request and decodes the response into T.
func getJSON(url string, v any) error {

	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp) //nolint:errcheck
		if errResp.Error != "" {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}

	if err := json.Unmarshal(respBody, v); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

// postJSON sends a JSON POST request and decodes the response into T.
func postJSON(url string, body any, v any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data)) //nolint:noctx
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp) //nolint:errcheck
		if errResp.Error != "" {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}

	if err := json.Unmarshal(respBody, v); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func getIssuedCert(apiUrl string, kind string, cn string) (cert.IssuedCert, error) {
	var v cert.IssuedCert
	url := fmt.Sprintf("%s/certs/by-cn?type=%s&cn=%s", apiUrl, kind, cn)
	err := getJSON(url, &v)
	if err != nil {
		return v, err
	}

	return v, nil
}
