package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
)

const (
	ConfigFileName = "config.json"
)

// Config represents the global settings for Maknoon.
type Config struct {
	DefaultIdentity string                     `json:"default_identity"`
	Security        SecurityConfig             `json:"security"`
	Performance     PerformanceConfig          `json:"performance"`
	Nostr           NostrConfig                `json:"nostr"`
	Paths           PathConfig                 `json:"paths"`
	Profiles        map[string]*DynamicProfile `json:"profiles,omitempty"`
}

type SecurityConfig struct {
	ArgonTime    uint32 `json:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory"`
	ArgonThreads uint8  `json:"argon_threads"`
}

type PerformanceConfig struct {
	Concurrency      int  `json:"concurrency"`
	CompressionLevel int  `json:"compression_level"`
	DefaultStealth   bool `json:"default_stealth"`
}

type NostrConfig struct {
	Relays          []string `json:"relays"`
	BootstrapRelays []string `json:"bootstrap_relays"`
	PublishMetadata bool     `json:"publish_metadata"`
}

type PathConfig struct {
	KeysDir   string `json:"keys_dir"`
	VaultsDir string `json:"vaults_dir"`
}

var (
	globalConfig *Config
	configMu     sync.RWMutex
)

// DefaultConfig returns the standard fallback settings.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		DefaultIdentity: "default",
		Security: SecurityConfig{
			ArgonTime:    3,
			ArgonMemory:  64 * 1024,
			ArgonThreads: 4,
		},
		Performance: PerformanceConfig{
			Concurrency:      0,
			CompressionLevel: 3,
			DefaultStealth:   false,
		},
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
			PublishMetadata: true,
		},
		Paths: PathConfig{
			KeysDir:   filepath.Join(home, MaknoonDir, KeysDir),
			VaultsDir: filepath.Join(home, MaknoonDir, VaultsDir),
		},
		Profiles: make(map[string]*DynamicProfile),
	}
}

// Validate checks for logical errors in the configuration.
func (c *Config) Validate() error {
	if c.Security.ArgonMemory < 1024 {
		return errors.New("security.argon_memory must be at least 1024 KB")
	}
	if c.Security.ArgonTime < 1 {
		return errors.New("security.argon_time must be at least 1")
	}
	if c.Security.ArgonThreads < 1 {
		return errors.New("security.argon_threads must be at least 1")
	}

	for _, r := range c.Nostr.Relays {
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
			return fmt.Errorf("invalid nostr relay URL: %s (must be ws:// or wss://)", r)
		}
	}

	if c.Paths.KeysDir == "" || c.Paths.VaultsDir == "" {
		return errors.New("system paths cannot be empty")
	}

	return nil
}

// LoadConfig reads the config from ~/.maknoon/config.json.
func LoadConfig() (*Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	if globalConfig != nil {
		return globalConfig, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfig(), nil
	}

	path := filepath.Join(home, MaknoonDir, ConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, return memory default without error
		return DefaultConfig(), nil
	}

	conf := DefaultConfig()
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("config file is corrupted (invalid JSON): %w", err)
	}

	// Validate the loaded config
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Register custom profiles
	for _, dp := range conf.Profiles {
		RegisterProfile(dp)
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
	if c == nil {
		return DefaultConfig()
	}
	return c
}
