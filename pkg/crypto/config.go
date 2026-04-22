package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const (
	ConfigFileName = "config.json"
)

// Config represents the global settings for Maknoon.
type Config struct {
	DefaultIdentity string      `json:"default_identity"`
	Nostr           NostrConfig `json:"nostr"`
	IPFS            IPFSConfig  `json:"ipfs"`
}

type NostrConfig struct {
	Relays          []string `json:"relays"`
	BootstrapRelays []string `json:"bootstrap_relays"`
}

type IPFSConfig struct {
	Gateway string `json:"gateway"`
	Api     string `json:"api"`
}

var (
	globalConfig *Config
	configMu     sync.RWMutex
)

// DefaultConfig returns the standard fallback settings.
func DefaultConfig() *Config {
	return &Config{
		DefaultIdentity: "default",
		Nostr: NostrConfig{
			Relays: []string{
				"wss://relay.damus.io",
				"wss://nos.lol",
				"wss://relay.nostr.band",
			},
			BootstrapRelays: []string{
				"wss://relay.damus.io",
				"wss://nos.lol",
			},
		},
		IPFS: IPFSConfig{
			Gateway: "https://ipfs.io",
			Api:     "http://127.0.0.1:5001",
		},
	}
}

// LoadConfig reads the config from ~/.maknoon/config.json or returns defaults.
func LoadConfig() (*Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	if globalConfig != nil {
		return globalConfig, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		globalConfig = DefaultConfig()
		return globalConfig, nil
	}

	path := filepath.Join(home, MaknoonDir, ConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		globalConfig = DefaultConfig()
		return globalConfig, nil
	}

	conf := DefaultConfig()
	if err := json.Unmarshal(data, conf); err != nil {
		globalConfig = DefaultConfig()
		return globalConfig, nil
	}

	globalConfig = conf
	return globalConfig, nil
}

// Save persists the configuration to disk.
func (c *Config) Save() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path := filepath.Join(home, MaknoonDir, ConfigFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// GetGlobalConfig is a thread-safe helper to get the active config.
func GetGlobalConfig() *Config {
	c, _ := LoadConfig()
	return c
}
