package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newRevokeCmd(opts *rootOptions) *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "revoke <serial>",
		Short: "Revoke a certificate",
		Long:  `Revoke a certificate by serial number. Calls POST /certs/{serial}/revoke.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			serial := args[0]

			body := struct {
				Reason string `json:"reason"`
			}{
				Reason: reason,
			}

			var resp struct {
				Serial    string    `json:"serial"`
				RevokedAt time.Time `json:"revoked_at"`
				Reason    string    `json:"reason"`
			}

			if err := postJSON(opts.APIURL+"/certs/"+serial+"/revoke", body, &resp); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Revoked certificate %s at %s (reason: %s)\n",
				resp.Serial, resp.RevokedAt.Format(time.RFC3339), resp.Reason)
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "unspecified", "revocation reason (unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold)")

	return cmd
}
