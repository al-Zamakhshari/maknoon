package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// InfoCmd returns the cobra command for inspecting Maknoon files.
func InfoCmd() *cobra.Command {
	var stealth bool
	cmd := &cobra.Command{
		Use:   "info [file]",
		Short: "Inspect a Maknoon encrypted file's metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			filePath := args[0]
			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()

			var magic string
			var profileID byte
			var flags byte

			if stealth {
				header := make([]byte, 2)
				if _, err := io.ReadFull(f, header); err != nil {
					return fmt.Errorf("invalid file: stealth header too short")
				}
				profileID = header[0]
				flags = header[1]
				magic = "STEALTH"
			} else {
				header := make([]byte, 6)
				if _, err := io.ReadFull(f, header); err != nil {
					return fmt.Errorf("invalid file: header too short")
				}
				magic = string(header[:4])
				profileID = header[4]
				flags = header[5]
			}

			if JSONOutput {
				return printInfoJSON(magic, profileID, flags, filePath)
			}

			fmt.Printf("File: %s\n", filePath)
			fmt.Printf("----------------------------------------\n")

			switch magic {
			case crypto.MagicHeader:
				fmt.Println("Type:           Symmetric (Passphrase Protected)")
			case crypto.MagicHeaderAsym:
				fmt.Println("Type:           Asymmetric (Public Key Protected)")
			case "STEALTH":
				fmt.Println("Type:           Stealth (Fingerprint Resistant)")
			default:
				return fmt.Errorf("not a valid Maknoon file (invalid magic: %s)", magic)
			}

			fmt.Printf("Profile ID:     %d\n", profileID)

			isCompressed := flags&crypto.FlagCompress != 0
			isArchive := flags&crypto.FlagArchive != 0
			isSigned := flags&crypto.FlagSigned != 0

			fmt.Printf("Compression:    %v\n", isCompressed)
			fmt.Printf("Archive:        %v\n", isArchive)
			fmt.Printf("Signed:         %v\n", isSigned)

			profile, err := crypto.GetProfile(profileID, f)
			if err == nil {
				fmt.Printf("KEM Algorithm:  %s\n", profile.KEMName())
				fmt.Printf("SIG Algorithm:  %s\n", profile.SIGName())

				if v1, ok := profile.(*crypto.ProfileV1); ok {
					fmt.Printf("KDF Algorithm:  Argon2id (t=%d, m=%d, p=%d)\n", v1.ArgonTime, v1.ArgonMem, v1.ArgonThrd)
				}
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")
	return cmd
}

func printInfoJSON(magic string, profileID byte, flags byte, path string) error {
	type info struct {
		Path       string `json:"path"`
		Type       string `json:"type"`
		ProfileID  byte   `json:"profile_id"`
		Compressed bool   `json:"compressed"`
		IsArchive  bool   `json:"is_archive"`
		IsSigned   bool   `json:"is_signed"`
		IsStealth  bool   `json:"is_stealth"`
	}

	res := info{
		Path:       path,
		ProfileID:  profileID,
		Compressed: flags&crypto.FlagCompress != 0,
		IsArchive:  flags&crypto.FlagArchive != 0,
		IsSigned:   flags&crypto.FlagSigned != 0,
		IsStealth:  magic == "STEALTH" || (flags&crypto.FlagStealth != 0),
	}

	if magic == crypto.MagicHeader {
		res.Type = "symmetric"
	} else if magic == crypto.MagicHeaderAsym {
		res.Type = "asymmetric"
	} else if magic == "STEALTH" {
		res.Type = "stealth"
	}

	printJSON(res)
	return nil
}
