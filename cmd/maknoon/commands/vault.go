package commands

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"go.etcd.io/bbolt"
	"golang.org/x/term"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
)

var vaultName string
var vaultPassphrase string

func VaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")
	cmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "s", "", "Master passphrase for the vault")

	cmd.AddCommand(vaultSetCmd())
	cmd.AddCommand(vaultGetCmd())
	cmd.AddCommand(vaultListCmd())

	return cmd
}

func openVault() (*bbolt.DB, []byte, error) {
	crypto.EnsureMaknoonDirs()

	dbPath := vaultName
	if !strings.Contains(vaultName, string(os.PathSeparator)) {
		home, _ := os.UserHomeDir()
		dbPath = filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".db")
	}

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, nil, err
	}

	var salt []byte
	db.Update(func(tx *bbolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte(metaBucket))
		tx.CreateBucketIfNotExists([]byte(vaultBucket))
		salt = b.Get([]byte(saltKey))
		if salt == nil {
			salt = make([]byte, 32)
			rand.Read(salt)
			b.Put([]byte(saltKey), salt)
		}
		return nil
	})

	var passphrase []byte
	if vaultPassphrase != "" {
		passphrase = []byte(vaultPassphrase)
	} else if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		passphrase = []byte(env)
	} else {
		fmt.Print("Enter Vault Master Passphrase: ")
		p, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		passphrase = p
	}

	masterKey := crypto.DeriveVaultKey(passphrase, salt)
	crypto.SafeClear(passphrase)

	return db, masterKey, nil
}

func vaultSetCmd() *cobra.Command {
	var user, note string
	cmd := &cobra.Command{
		Use:  "set [service] [password]",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			service := args[0]
			var password string
			if len(args) > 1 {
				password = args[1]
			} else {
				fmt.Print("Enter password for ", service, ": ")
				p, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				password = string(p)
			}

			db, key, err := openVault()
			if err != nil {
				return err
			}
			defer db.Close()
			defer crypto.SafeClear(key)

			entry := &crypto.VaultEntry{Service: service, Username: user, Password: password, Note: note}
			ciphertext, _ := crypto.SealEntry(entry, key)

			h := sha256.Sum256([]byte(strings.ToLower(service)))
			return db.Update(func(tx *bbolt.Tx) error {
				return tx.Bucket([]byte(vaultBucket)).Put([]byte(hex.EncodeToString(h[:])), ciphertext)
			})
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "Username")
	cmd.Flags().StringVarP(&note, "note", "n", "", "Optional note")
	return cmd
}

func vaultGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "get [service]",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service := args[0]
			db, key, err := openVault()
			if err != nil {
				return err
			}
			defer db.Close()
			defer crypto.SafeClear(key)

			h := sha256.Sum256([]byte(strings.ToLower(service)))
			var ciphertext []byte
			db.View(func(tx *bbolt.Tx) error {
				ciphertext = tx.Bucket([]byte(vaultBucket)).Get([]byte(hex.EncodeToString(h[:])))
				return nil
			})

			if ciphertext == nil {
				return fmt.Errorf("service not found")
			}
			entry, err := crypto.OpenEntry(ciphertext, key)
			if err != nil {
				return err
			}

			fmt.Printf("Service:  %s\nUsername: %s\nPassword: %s\n", entry.Service, entry.Username, entry.Password)
			return nil
		},
	}
}

func vaultListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, key, err := openVault()
			if err != nil {
				return err
			}
			defer db.Close()
			defer crypto.SafeClear(key)

			return db.View(func(tx *bbolt.Tx) error {
				return tx.Bucket([]byte(vaultBucket)).ForEach(func(k, v []byte) error {
					entry, err := crypto.OpenEntry(v, key)
					if err == nil {
						fmt.Printf(" - %s (%s)\n", entry.Service, entry.Username)
					}
					return nil
				})
			})
		},
	}
}
