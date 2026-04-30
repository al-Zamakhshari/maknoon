package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.etcd.io/bbolt"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
	fido2Key    = "fido2"
)

var vaultName string
var vaultPassphrase string
var useFido2 bool

// VaultCmd returns the cobra command for managing secure vaults.
func VaultCmd() *cobra.Command {
	vaultName = "default" // Reset to default
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")
	cmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "s", "", "Master passphrase for the vault")
	cmd.PersistentFlags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")

	_ = cmd.RegisterFlagCompletionFunc("vault", completeVaults)

	cmd.AddCommand(vaultSetCmd())
	cmd.AddCommand(vaultGetCmd())
	cmd.AddCommand(vaultListCmd())
	cmd.AddCommand(vaultRenameCmd())
	cmd.AddCommand(vaultDeleteCmd())
	cmd.AddCommand(vaultSplitCmd())
	cmd.AddCommand(vaultRecoverCmd())

	return cmd
}

func vaultSplitCmd() *cobra.Command {
	var threshold, shares int
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Shard the vault's master access key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()

			// Get the raw passphrase used for the vault
			var pass []byte
			var err error
			if vaultPassphrase != "" {
				pass = []byte(vaultPassphrase)
			} else {
				pass, _, err = getPassphrase("Enter Vault Master Passphrase to shard: ")
				if err != nil {
					p.RenderError(err)
					return nil
				}
			}
			defer crypto.SafeClear(pass)

			h := sha256.Sum256(pass)
			fmt.Fprintf(os.Stderr, "DEBUG: Original Passphrase Hash: %x\n", h)

			shards, err := crypto.SplitSecret(pass, threshold, shares)
			if err != nil {
				p.RenderError(err)
				return nil
			}

			if GlobalContext.UI.JSON {
				var jsonShards []string
				for _, s := range shards {
					jsonShards = append(jsonShards, s.ToMnemonic())
				}
				p.RenderSuccess(crypto.VaultResult{
					Vault:     vaultName,
					Threshold: threshold,
					Shares:    jsonShards,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🛡️  Vault '%s' access sharded into %d parts (Threshold: %d)", vaultName, shares, threshold))
				p.RenderMessage("CRITICAL: These shards represent the derived MASTER KEY. Keep them safe.")
				for i, s := range shards {
					p.RenderMessage(fmt.Sprintf("\nShare %d:\n%s", i+1, s.ToMnemonic()))
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Minimum shares required for reconstruction")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total number of shares to generate")
	return cmd
}

func vaultRecoverCmd() *cobra.Command {
	var targetPath string
	cmd := &cobra.Command{
		Use:   "recover [shards...]",
		Short: "Recover vault contents using shards and optionally save to a new vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			if len(args) == 0 {
				p.RenderError(fmt.Errorf("at least one shard mnemonic is required"))
				return nil
			}

			var shards []crypto.Share
			for _, m := range args {
				s, err := crypto.FromMnemonic(m)
				if err != nil {
					p.RenderError(fmt.Errorf("invalid mnemonic: %w", err))
					return nil
				}
				shards = append(shards, *s)
			}

			passphrase, err := crypto.CombineShares(shards)
			if err != nil {
				p.RenderError(err)
				return nil
			}
			defer crypto.SafeClear(passphrase)

			h := sha256.Sum256(passphrase)
			fmt.Fprintf(os.Stderr, "DEBUG: Reconstructed Passphrase Hash: %x\n", h)

			dbPath, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return nil
			}
			db, err := bbolt.Open(dbPath, 0600, nil)
			if err != nil {
				p.RenderError(err)
				return nil
			}
			defer db.Close()

			var masterKey []byte
			var entries []*crypto.VaultEntry
			err = db.View(func(tx *bbolt.Tx) error {
				meta := tx.Bucket([]byte(metaBucket))
				if meta == nil {
					return fmt.Errorf("vault metadata not found")
				}
				salt := meta.Get([]byte(saltKey))
				if salt == nil {
					return fmt.Errorf("vault salt not found")
				}
				masterKey = crypto.DeriveVaultKey(passphrase, salt)

				b := tx.Bucket([]byte(vaultBucket))
				if b == nil {
					return nil
				}
				return b.ForEach(func(_ []byte, v []byte) error {
					entry, err := crypto.OpenEntry(v, masterKey)
					if err == nil {
						entries = append(entries, entry)
					}
					return nil
				})
			})
			if masterKey != nil {
				defer crypto.SafeClear(masterKey)
			}

			if err != nil {
				p.RenderError(err)
				return nil
			}

			if len(entries) == 0 {
				p.RenderError(fmt.Errorf("no entries recovered. Check your shards and master key"))
				return nil
			}

			if targetPath != "" {
				// Save to a new vault with a new passphrase
				pass, _, err := getPassphrase("Enter new master passphrase for recovery vault: ")
				if err != nil {
					p.RenderError(err)
					return nil
				}
				defer crypto.SafeClear(pass)

				newVaultPath, err := resolveVaultPath(targetPath)
				if err != nil {
					p.RenderError(err)
					return nil
				}
				newDb, err := bbolt.Open(newVaultPath, 0600, nil)
				if err != nil {
					p.RenderError(err)
					return nil
				}
				defer newDb.Close()

				salt := make([]byte, 32)
				rand.Read(salt)
				newMasterKey := crypto.DeriveVaultKey(pass, salt)
				defer crypto.SafeClear(newMasterKey)

				err = newDb.Update(func(tx *bbolt.Tx) error {
					meta, _ := tx.CreateBucketIfNotExists([]byte(metaBucket))
					meta.Put([]byte(saltKey), salt)
					b, _ := tx.CreateBucketIfNotExists([]byte(vaultBucket))
					for _, e := range entries {
						ciphertext, _ := crypto.SealEntry(e, newMasterKey)
						h := sha256.Sum256([]byte(strings.ToLower(e.Service)))
						b.Put([]byte(hex.EncodeToString(h[:])), ciphertext)
					}
					return nil
				})
				if err != nil {
					p.RenderError(err)
					return nil
				}

				p.RenderSuccess(crypto.VaultResult{
					Status:           "success",
					RecoveredEntries: len(entries),
					Output:           newVaultPath,
				})
			} else {
				if GlobalContext.UI.JSON {
					type recoveredEntry struct {
						Service  string `json:"service"`
						Username string `json:"username"`
						Password string `json:"password"`
					}
					var recs []recoveredEntry
					for _, e := range entries {
						recs = append(recs, recoveredEntry{
							Service:  e.Service,
							Username: e.Username,
							Password: string(e.Password),
						})
						crypto.SafeClear(e.Password)
					}
					p.RenderSuccess(recs)
				} else {
					p.RenderMessage(fmt.Sprintf("🛡️  Recovered %d entries from vault '%s':", len(entries), vaultName))
					for _, e := range entries {
						p.RenderMessage(fmt.Sprintf("  - %s (User: %s, Pass: %s)", e.Service, e.Username, string(e.Password)))
						crypto.SafeClear(e.Password)
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&targetPath, "output", "o", "", "Path to save recovered entries as a new vault")
	return cmd
}

func resolveVaultPath(name string) (string, error) {
	home := crypto.GetUserHomeDir()
	defaultDir := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir)

	if strings.Contains(name, string(os.PathSeparator)) {
		if err := validatePath(name); err != nil {
			return "", err
		}
		return name, nil
	}
	return filepath.Join(defaultDir, name+".vault"), nil
}

func openVault() (*bbolt.DB, []byte, error) {
	checkJSONMode(nil)
	if err := crypto.EnsureMaknoonDirs(); err != nil {
		return nil, nil, err
	}

	dbPath, err := resolveVaultPath(vaultName)
	if err != nil {
		return nil, nil, err
	}

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open vault database: %w", err)
	}

	var salt []byte
	var fido2Raw []byte
	var fido2Secret []byte

	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(vaultBucket)); err != nil {
			return err
		}
		salt = b.Get([]byte(saltKey))
		if salt == nil {
			salt = make([]byte, 32)
			if _, err := rand.Read(salt); err != nil {
				return err
			}
			if err := b.Put([]byte(saltKey), salt); err != nil {
				return err
			}
		}
		fido2Raw = b.Get([]byte(fido2Key))

		if useFido2 && fido2Raw == nil {
			pin, err := getPIN()
			if err != nil {
				return err
			}
			meta, secret, err := crypto.Fido2Enroll("maknoon.io", "vault-user", pin)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(fido2Key), raw); err != nil {
				return err
			}
			fido2Raw = raw
			fido2Secret = secret
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	var passphrase []byte
	if len(fido2Secret) > 0 {
		passphrase = fido2Secret
	} else if fido2Raw != nil {
		var meta crypto.Fido2Metadata
		if err := json.Unmarshal(fido2Raw, &meta); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		pin, err := getPIN()
		if err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		secret, err := crypto.Fido2Derive(meta.RPID, meta.CredentialID, pin)
		if err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		passphrase = secret
	}

	if len(passphrase) == 0 {
		if vaultPassphrase != "" {
			passphrase = []byte(vaultPassphrase)
		} else {
			var err error
			passphrase, _, err = getPassphrase("Enter Vault Master Passphrase: ")
			if err != nil {
				_ = db.Close()
				return nil, nil, err
			}
		}
	}

	masterKey := crypto.DeriveVaultKey(passphrase, salt)
	crypto.SafeClear(passphrase)

	return db, masterKey, nil
}

func vaultSetCmd() *cobra.Command {
	var user, note string
	cmd := &cobra.Command{
		Use:               "set [service]",
		Short:             "Store a secret in the vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeServices,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			service := args[0]
			var password []byte
			var err error

			if env := viper.GetString("password"); env != "" {
				password = []byte(env)
			} else {
				var err error
				password, _, err = getPassphrase(fmt.Sprintf("Enter password for %s: ", service))
				if err != nil {
					p.RenderError(err)
					return nil
				}
			}
			defer crypto.SafeClear(password)

			db, key, err := openVault()
			if err != nil {
				p.RenderError(err)
				return nil
			}
			defer func() { _ = db.Close() }()
			defer crypto.SafeClear(key)

			entry := &crypto.VaultEntry{Service: service, Username: user, Password: password, Note: note}
			ciphertext, err := crypto.SealEntry(entry, key)
			if err != nil {
				p.RenderError(err)
				return nil
			}

			h := sha256.Sum256([]byte(strings.ToLower(service)))
			err = db.Update(func(tx *bbolt.Tx) error {
				return tx.Bucket([]byte(vaultBucket)).Put([]byte(hex.EncodeToString(h[:])), ciphertext)
			})
			if err != nil {
				p.RenderError(err)
				return nil
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Service: service,
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "Username")
	cmd.Flags().StringVarP(&note, "note", "n", "", "Optional note")
	return cmd
}

func vaultGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "get [service]",
		Short:             "Retrieve a secret from the vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeServices,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			service := args[0]
			db, key, err := openVault()
			if err != nil {
				p.RenderError(err)
				return nil
			}
			defer func() { _ = db.Close() }()
			defer crypto.SafeClear(key)

			h := sha256.Sum256([]byte(strings.ToLower(service)))
			var ciphertext []byte
			err = db.View(func(tx *bbolt.Tx) error {
				b := tx.Bucket([]byte(vaultBucket))
				if b == nil {
					return fmt.Errorf("vault bucket not found")
				}
				ciphertext = b.Get([]byte(hex.EncodeToString(h[:])))
				return nil
			})
			if err != nil {
				p.RenderError(err)
				return nil
			}

			if ciphertext == nil {
				p.RenderError(fmt.Errorf("service not found"))
				return nil
			}
			entry, err := crypto.OpenEntry(ciphertext, key)
			if err != nil {
				p.RenderError(err)
				return nil
			}

			if GlobalContext.UI.JSON {
				type jsonEntry struct {
					Service  string `json:"service"`
					Username string `json:"username"`
					Password string `json:"password"`
					Note     string `json:"note"`
				}
				p.RenderSuccess(jsonEntry{
					Service:  entry.Service,
					Username: entry.Username,
					Password: string(entry.Password),
					Note:     entry.Note,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("Service:  %s\nUsername: %s\nPassword: %s", entry.Service, entry.Username, string(entry.Password)))
			}
			crypto.SafeClear(entry.Password)
			return nil
		},
	}
	return cmd
}

func vaultListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all services stored in the vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()
			db, key, err := openVault()
			if err != nil {
				p.RenderError(err)
				return nil
			}
			defer func() { _ = db.Close() }()
			defer crypto.SafeClear(key)

			var services []crypto.VaultListEntry
			err = db.View(func(tx *bbolt.Tx) error {
				b := tx.Bucket([]byte(vaultBucket))
				if b == nil {
					return nil
				}
				return b.ForEach(func(_ []byte, v []byte) error {
					entry, err := crypto.OpenEntry(v, key)
					if err == nil {
						services = append(services, crypto.VaultListEntry{
							Service:  entry.Service,
							Username: entry.Username,
						})
					}
					return nil
				})
			})

			if err != nil {
				p.RenderError(err)
				return nil
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(services)
			} else {
				for _, s := range services {
					p.RenderMessage(fmt.Sprintf(" - %s (%s)", s.Service, s.Username))
				}
			}
			return nil
		},
	}
	return cmd
}

func vaultRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename [old_name] [new_name]",
		Short: "Rename a local vault file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			oldPath, err := resolveVaultPath(args[0])
			if err != nil {
				p.RenderError(err)
				return nil
			}
			newPath, err := resolveVaultPath(args[1])
			if err != nil {
				p.RenderError(err)
				return nil
			}

			if _, err := os.Stat(oldPath); err != nil {
				p.RenderError(fmt.Errorf("vault '%s' not found", args[0]))
				return nil
			}
			if _, err := os.Stat(newPath); err == nil {
				p.RenderError(fmt.Errorf("target vault '%s' already exists", args[1]))
				return nil
			}

			if err := os.Rename(oldPath, newPath); err != nil {
				p.RenderError(err)
				return nil
			}

			p.RenderSuccess(crypto.VaultResult{
				Status: "success",
				Vault:  args[1], // New name
			})
			return nil
		},
	}
	return cmd
}

func vaultDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Permanently delete a vault file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			path, err := resolveVaultPath(args[0])
			if err != nil {
				p.RenderError(err)
				return nil
			}

			if _, err := os.Stat(path); err != nil {
				p.RenderError(fmt.Errorf("vault '%s' not found", args[0]))
				return nil
			}

			if !GlobalContext.UI.JSON {
				fmt.Printf("ARE YOU SURE you want to delete vault '%s'? This cannot be undone. (y/N): ", args[0])
				var confirm string
				fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" {
					p.RenderError(fmt.Errorf("deletion cancelled"))
					return nil
				}
			}

			if err := GlobalContext.Engine.SecureDelete(path); err != nil {
				p.RenderError(err)
				return nil
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Deleted: args[0],
			})
			return nil
		},
	}
	return cmd
}
