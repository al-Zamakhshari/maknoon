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
	DefaultIdentity string            `json:"default_identity"`
	Security        SecurityConfig    `json:"security"`
	Performance     PerformanceConfig `json:"performance"`
	Nostr           NostrConfig       `json:"nostr"`
	Paths           PathConfig        `json:"paths"`
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
	PublishMetadata bool     `json:"publish_metadata"` // Toggle the "Maknoon Enabled" about note
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
			ArgonMemory:  64 * 1024, // 64MB
			ArgonThreads: 4,
		},
		Performance: PerformanceConfig{
			Concurrency:      0, // Auto
			CompressionLevel: 3, // Zstd default
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
