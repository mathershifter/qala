package cli

import (
	// "context"
	// "errors"
	"fmt"
	// "net/http"
	// "os"
	// "os/signal"
	"path/filepath"
	// "syscall"
	// "time"

	"github.com/spf13/cobra"

	api "gitlab.aristanetworks.com/jmather/qala/internal/api/v1"
	"gitlab.aristanetworks.com/jmather/qala/internal/ca"
	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
	"gitlab.aristanetworks.com/jmather/qala/internal/ports"
	"gitlab.aristanetworks.com/jmather/qala/internal/store"
)

func newServeCmd(opts *rootOptions) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the certificate signing OpenAPI REST server",
		RunE: func(_ *cobra.Command, _ []string) error {
			logger := buildLogger(opts)

			loadedCA, err := ca.Load(opts.DataDir, logger)
			if err != nil {
				return fmt.Errorf("load CA: %w (run 'qala init' first)", err)
			}

			dbPath := filepath.Join(opts.DataDir, "qala.db")
			st, err := store.New(dbPath, logger)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			svc := cert.NewService(loadedCA, st, logger)
			srv := api.NewCertsService(svc, loadedCA, logger)
			h := api.HandlerWithOptions(srv, api.StdHTTPServerOptions{
				ErrorHandlerFunc: api.JSONErrorHandler,
				Middlewares: []api.MiddlewareFunc{
					ports.CORSMiddleware,
				},
			})
			return ports.HTTPServer(addr, h, logger)
		},
	}

	cmd.Flags().StringVar(&addr, "addr",
		envOrDefault("QALA_ADDR", "0.0.0.0:8080"), "listen address")

	return cmd
}
