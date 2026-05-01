package commands

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func ContactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contact",
		Short: "Manage local trusted contacts (Petnames)",
	}

	cmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")

	cmd.AddCommand(contactAddCmd())
	cmd.AddCommand(contactListCmd())
	cmd.AddCommand(contactRemoveCmd())

	return cmd
}

func contactAddCmd() *cobra.Command {
	var kemPubPath, sigPubPath, note, peerID string
	cmd := &cobra.Command{
		Use:   "add [petname]",
		Short: "Add a new trusted contact",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			petname := args[0]
			if !strings.HasPrefix(petname, "@") {
				petname = "@" + petname
			}

			if kemPubPath == "" {
				return fmt.Errorf("--kem-pub is required")
			}

			kemPub, err := os.ReadFile(kemPubPath)
			if err != nil {
				return fmt.Errorf("failed to read KEM public key: %w", err)
			}

			var sigPub []byte
			if sigPubPath != "" {
				sigPub, err = os.ReadFile(sigPubPath)
				if err != nil {
					return fmt.Errorf("failed to read SIG public key: %w", err)
				}
			}

			err = GlobalContext.Engine.ContactAdd(nil, petname, hex.EncodeToString(kemPub), hex.EncodeToString(sigPub), note)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{"status": "success", "petname": petname})
			} else {
				p.RenderMessage(fmt.Sprintf("✅ Contact '%s' added successfully.", petname))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&kemPubPath, "kem-pub", "", "Path to the contact's ML-KEM public key")
	cmd.Flags().StringVar(&sigPubPath, "sig-pub", "", "Path to the contact's ML-DSA public key")
	cmd.Flags().StringVar(&peerID, "peer-id", "", "Explicit libp2p Peer ID (optional)")
	cmd.Flags().StringVarP(&note, "note", "n", "", "Optional note for this contact")

	return cmd
}

func contactListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all trusted contacts",
		RunE: func(_ *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()
			contacts, err := GlobalContext.Engine.ContactList(nil)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(contacts)
			} else {
				if len(contacts) == 0 {
					p.RenderMessage("No contacts found.")
					return nil
				}
				p.RenderMessage(fmt.Sprintf("%-20s %-45s %-12s %s", "PETNAME", "PEER ID", "ADDED", "NOTES"))
				p.RenderMessage(strings.Repeat("-", 100))
				for _, c := range contacts {
					p.RenderMessage(fmt.Sprintf("%-20s %-45s %-12s %s", c.Petname, c.PeerID, c.AddedAt.Format("2006-01-02"), c.Notes))
				}
			}
			return nil
		},
	}
	return cmd
}

func contactRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove [petname]",
		Short: "Remove a contact from your address book",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			petname := args[0]
			if !strings.HasPrefix(petname, "@") {
				petname = "@" + petname
			}

			if err := GlobalContext.Engine.ContactDelete(nil, petname); err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{"status": "success", "removed": petname})
			} else {
				p.RenderMessage(fmt.Sprintf("🗑️  Contact '%s' removed.", petname))
			}
			return nil
		},
	}
	return cmd
}
