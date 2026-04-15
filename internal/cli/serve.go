package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	api "gitlab.aristanetworks.com/jmather/qala/internal/api/v1"
	"gitlab.aristanetworks.com/jmather/qala/internal/ca"
	"gitlab.aristanetworks.com/jmather/qala/internal/cert"
	"gitlab.aristanetworks.com/jmather/qala/internal/crl"
	"gitlab.aristanetworks.com/jmather/qala/internal/ports"
	"gitlab.aristanetworks.com/jmather/qala/internal/store"

	"github.com/rs/cors"
)

func newServeCmd(opts *rootOptions) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the certificate signing OpenAPI REST server",
		RunE: func(_ *cobra.Command, _ []string) error {
			logger := buildLogger(opts)

			loadedCA, err := ca.LoadCA(opts.DataDir, logger)
			if err != nil {
				return fmt.Errorf("load CA: %w (run 'qala init' first)", err)
			}

			loadedCRL, err := crl.LoadOrInitCRL(opts.DataDir, loadedCA)
			if err != nil {
				return fmt.Errorf("init-or-load CRL: %w", err)
			}

			dbPath := filepath.Join(opts.DataDir, "qala.db")
			st, err := store.New(dbPath, logger)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			c := cors.New(cors.Options{
				AllowedOrigins: []string{"*"},
			})

			svc := cert.NewService(loadedCA, loadedCRL, st, logger)
			srv := api.NewCertsService(svc, loadedCA, loadedCRL, logger)
			h := api.HandlerWithOptions(srv, api.StdHTTPServerOptions{
				ErrorHandlerFunc: api.JSONErrorHandler,
				// Middlewares: []api.MiddlewareFunc{
				// 	ports.CORSMiddleware,
				// },
			})

			return ports.HTTPServer(addr, c.Handler(h), logger)
		},
	}

	cmd.Flags().StringVar(&addr, "addr",
		envOrDefault("QALA_ADDR", "0.0.0.0:8080"), "listen address")

	return cmd
}
