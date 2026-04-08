package cli

import (
	"fmt"
	"net/url"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"gitlab.aristanetworks.com/jmather/seacrt/internal/cert"
)

func newListCmd(opts *rootOptions) *cobra.Command {
	var (
		certType string
		expired  bool
		quiet    bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued certificates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			params := url.Values{}
			if certType != "" {
				params.Set("type", certType)
			}
			if expired {
				params.Set("expired", "true")
			}

			apiURL := opts.APIURL + "/certs"
			if len(params) > 0 {
				apiURL += "?" + params.Encode()
			}

			var result struct {
				Certs []cert.Summary `json:"certs"`
				Total int            `json:"total"`
			}
			if err := getJSON(apiURL, &result); err != nil {
				return err
			}

			if !quiet {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "SERIAL\tTYPE\tCOMMON NAME\tISSUED\tEXPIRES")
				for _, c := range result.Certs {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
						c.Serial,
						c.Type,
						c.CommonName,
						c.IssuedAt.Format("2006-01-02"),
						c.ExpiresAt.Format("2006-01-02"),
					)
				}
				w.Flush()

				fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d\n", result.Total)
			} else {
				for _, c := range result.Certs {
					fmt.Println(c.Serial)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&certType, "type", "", "filter by type: server or client")
	cmd.Flags().BoolVar(&expired, "expired", false, "include expired certificates")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "only display the serial")

	return cmd
}
