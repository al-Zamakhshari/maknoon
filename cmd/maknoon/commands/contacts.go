package commands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
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

			// Automatic PeerID Derivation if not provided
			if peerID == "" && len(sigPub) > 0 {
				peerID, _ = crypto.DerivePeerID(sigPub)
			}

			cm, err := crypto.NewContactManager()
			if err != nil {
				return err
			}
			defer cm.Close()

			contact := &crypto.Contact{
				Petname:   petname,
				KEMPubKey: kemPub,
				SIGPubKey: sigPub,
				PeerID:    peerID,
				AddedAt:   time.Now(),
				Notes:     note,
			}

			if err := cm.Add(contact); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "petname": petname, "peer_id": peerID})
			} else {
				fmt.Printf("✅ Contact '%s' added successfully.\n", petname)
				if peerID != "" {
					fmt.Printf("🆔 Derived PeerID: %s\n", peerID)
				}
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
			cm, err := crypto.NewContactManager()
			if err != nil {
				return err
			}
			defer cm.Close()

			contacts, err := cm.List()
			if err != nil {
				return err
			}

			if JSONOutput {
				printJSON(contacts)
			} else {
				if len(contacts) == 0 {
					fmt.Println("No contacts found.")
					return nil
				}
				fmt.Printf("%-20s %-45s %-12s %s\n", "PETNAME", "PEER ID", "ADDED", "NOTES")
				fmt.Println(strings.Repeat("-", 100))
				for _, c := range contacts {
					fmt.Printf("%-20s %-45s %-12s %s\n", c.Petname, c.PeerID, c.AddedAt.Format("2006-01-02"), c.Notes)
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
			petname := args[0]
			if !strings.HasPrefix(petname, "@") {
				petname = "@" + petname
			}

			cm, err := crypto.NewContactManager()
			if err != nil {
				return err
			}
			defer cm.Close()

			if err := cm.Delete(petname); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "removed": petname})
			} else {
				fmt.Printf("🗑️  Contact '%s' removed.\n", petname)
			}
			return nil
		},
	}
	return cmd
}
