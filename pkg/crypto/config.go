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
	DefaultIdentity    string                     `json:"default_identity"`
	IdentityRegistries []string                   `json:"identity_registries,omitempty"`
	Security           SecurityConfig             `json:"security"`
	Performance        PerformanceConfig          `json:"performance"`
	AgentLimits        AgentLimitsConfig          `json:"agent_limits"`
	Wormhole           WormholeConfig             `json:"wormhole"`
	Nostr              NostrConfig                `json:"nostr"`
	Paths              PathConfig                 `json:"paths"`
	Profiles           map[string]*DynamicProfile `json:"profiles,omitempty"`
}

type AgentLimitsConfig struct {
	MaxMemoryKB uint32   `json:"max_memory_kb"`
	MaxTime     uint32   `json:"max_time"`
	MaxThreads  uint8    `json:"max_threads"`
	MaxWorkers  int      `json:"max_workers"`
	AllowedURLs []string `json:"allowed_urls"`
}

type WormholeConfig struct {
	RendezvousURL string `json:"rendezvous_url"`
	TransitRelay  string `json:"transit_relay"`
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

// GetUserHomeDir returns the current user's home directory, respecting the HOME environment variable.
func GetUserHomeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// DefaultConfig returns the standard fallback settings.
func DefaultConfig() *Config {
	home := GetUserHomeDir()
	return &Config{
		DefaultIdentity:    "default",
		IdentityRegistries: []string{"dns", "nostr"},
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
		AgentLimits: AgentLimitsConfig{
			MaxMemoryKB: 512 * 1024, // 512MB
			MaxTime:     5,
			MaxThreads:  4,
			MaxWorkers:  2,
			AllowedURLs: []string{
				"wss://relay.magic-wormhole.io:4000/v1",
				"tcp:transit.magic-wormhole.io:4001",
			},
		},
		Wormhole: WormholeConfig{
			RendezvousURL: "wss://relay.magic-wormhole.io:4000/v1",
			TransitRelay:  "tcp:transit.magic-wormhole.io:4001",
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

	home := GetUserHomeDir()
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
	home := GetUserHomeDir()
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

// ResetGlobalConfig clears the cached config, forcing a reload on next use.
// Useful for tests that change environment variables like HOME.
func ResetGlobalConfig() {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig = nil
}
