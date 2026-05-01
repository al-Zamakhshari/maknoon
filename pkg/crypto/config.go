package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/spf13/viper"
)

const (
	ConfigFileName = "config.json"
)

// Config represents the global settings for Maknoon.
type Config struct {
	DefaultIdentity    string                     `json:"default_identity" mapstructure:"default_identity"`
	IdentityRegistries []string                   `json:"identity_registries,omitempty" mapstructure:"identity_registries"`
	Audit              AuditConfig                `json:"audit,omitempty" mapstructure:"audit"`
	Security           SecurityConfig             `json:"security" mapstructure:"security"`
	Performance        PerformanceConfig          `json:"performance" mapstructure:"performance"`
	AgentLimits        AgentLimitsConfig          `json:"agent_limits" mapstructure:"agent_limits"`
	Nostr              NostrConfig                `json:"nostr" mapstructure:"nostr"`
	Tunnel             tunnel.TunnelConfig        `json:"tunnel" mapstructure:"tunnel"`
	Paths              PathConfig                 `json:"paths" mapstructure:"paths"`
	Profiles           map[string]*DynamicProfile `json:"profiles,omitempty" mapstructure:"profiles"`
}

type AuditConfig struct {
	Enabled bool   `json:"enabled" mapstructure:"enabled"`
	LogFile string `json:"log_file" mapstructure:"log_file"`
}

type AgentLimitsConfig struct {
	MaxMemoryKB uint32   `json:"max_memory_kb" mapstructure:"max_memory_kb"`
	MaxTime     uint32   `json:"max_time" mapstructure:"max_time"`
	MaxThreads  uint8    `json:"max_threads" mapstructure:"max_threads"`
	MaxWorkers  int      `json:"max_workers" mapstructure:"max_workers"`
	AllowedURLs []string `json:"allowed_urls" mapstructure:"allowed_urls"`
}

type SecurityConfig struct {
	ArgonTime    uint32 `json:"argon_time" mapstructure:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory" mapstructure:"argon_memory"`
	ArgonThreads uint8  `json:"argon_threads" mapstructure:"argon_threads"`
}

type PerformanceConfig struct {
	Concurrency      int  `json:"concurrency" mapstructure:"concurrency"`
	CompressionLevel int  `json:"compression_level" mapstructure:"compression_level"`
	DefaultCompress  bool `json:"default_compress" mapstructure:"default_compress"`
	DefaultStealth   bool `json:"default_stealth" mapstructure:"default_stealth"`
	DefaultProfile   byte `json:"default_profile" mapstructure:"default_profile"`
}

type NostrConfig struct {
	Relays          []string `json:"relays" mapstructure:"relays"`
	BootstrapRelays []string `json:"bootstrap_relays" mapstructure:"bootstrap_relays"`
	PublishMetadata bool     `json:"publish_metadata" mapstructure:"publish_metadata"`
}

type PathConfig struct {
	KeysDir   string `json:"keys_dir" mapstructure:"keys_dir"`
	VaultsDir string `json:"vaults_dir" mapstructure:"vaults_dir"`
}

type TunnelConfig struct {
	MaxStreams       int `json:"max_streams" mapstructure:"max_streams"`
	IdleTimeout      int `json:"idle_timeout_sec" mapstructure:"idle_timeout_sec"`
	HandshakeTimeout int `json:"handshake_timeout_sec" mapstructure:"handshake_timeout_sec"`
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
		Audit: AuditConfig{
			Enabled: false,
			LogFile: filepath.Join(home, MaknoonDir, "audit.log"),
		},
		Security: SecurityConfig{
			ArgonTime:    3,
			ArgonMemory:  64 * 1024,
			ArgonThreads: 4,
		},
		Performance: PerformanceConfig{
			Concurrency:      0,
			CompressionLevel: 3,
			DefaultCompress:  false,
			DefaultStealth:   false,
			DefaultProfile:   1, // NIST/Hybrid
		},

		AgentLimits: AgentLimitsConfig{
			MaxMemoryKB: 512 * 1024, // 512MB
			MaxTime:     5,
			MaxThreads:  4,
			MaxWorkers:  2,
			AllowedURLs: []string{},
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
		Tunnel: tunnel.TunnelConfig{
			MaxStreams:       256,
			IdleTimeout:      30,
			HandshakeTimeout: 10,
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

// LoadConfig reads the config from ~/.maknoon/config.json, merged with environment variables.
func LoadConfig() (*Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	if globalConfig != nil {
		return globalConfig, nil
	}

	v := viper.New()
	// Setup standard environment variable bindings
	v.SetEnvPrefix("MAKNOON")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.BindEnv("performance.default_compress")
	_ = v.BindEnv("performance.default_stealth")
	_ = v.BindEnv("audit.enabled")
	_ = v.BindEnv("audit.log_file")
	_ = v.BindEnv("desec_token", "DESEC_TOKEN")

	home := GetUserHomeDir()
	configPath := filepath.Join(home, MaknoonDir, ConfigFileName)
	v.SetConfigFile(configPath)

	// Read from file if it exists
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	conf := DefaultConfig()
	if err := v.Unmarshal(conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate the resulting config
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
