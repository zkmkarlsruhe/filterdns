package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const (
	appName     = "FilterDNS"
	configFile  = "config.json"
	keyringName = "filterdns-client"
)

// Build-time variables (set via -ldflags)
var (
	// DefaultServerURL is the default FilterDNS server URL.
	// For development, this is localhost:8080.
	// For production builds, override via -ldflags:
	//   -ldflags "-X github.com/zkmkarlsruhe/filterdns-client/internal/config.DefaultServerURL=https://filterdns.example.com"
	DefaultServerURL = "http://localhost:8080"
)

// Forwarder represents a split DNS forwarder rule
type Forwarder struct {
	Domain string `json:"domain"` // e.g., "ts.net", "*.internal"
	Server string `json:"server"` // e.g., "100.100.100.100", "192.168.1.1:53"
}

// Config holds the application configuration
type Config struct {
	Profile    string      `json:"profile"`    // FilterDNS profile name
	ServerURL  string      `json:"serverUrl"`  // FilterDNS server URL
	Enabled    bool        `json:"enabled"`    // Whether filtering is enabled
	Autostart  bool        `json:"autostart"`  // Start on system boot
	Forwarders []Forwarder `json:"forwarders"` // Split DNS forwarders
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Profile:    "",
		ServerURL:  DefaultServerURL,
		Enabled:    false,
		Autostart:  false,
		Forwarders: []Forwarder{},
	}
}

// configDir returns the configuration directory path
func configDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(configDir, appName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

// configPath returns the full path to the config file
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFile), nil
}

// Load reads the configuration from disk
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, err
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Apply defaults for missing fields
	if cfg.ServerURL == "" {
		cfg.ServerURL = DefaultServerURL
	}
	if cfg.Forwarders == nil {
		cfg.Forwarders = []Forwarder{}
	}

	return cfg, nil
}

// Save writes the configuration to disk
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// SetPassword stores the password securely in the OS keychain
func SetPassword(profile, password string) error {
	return keyring.Set(keyringName, profile, password)
}

// GetPassword retrieves the password from the OS keychain
func GetPassword(profile string) (string, error) {
	password, err := keyring.Get(keyringName, profile)
	if err == keyring.ErrNotFound {
		return "", nil
	}
	return password, err
}

// DeletePassword removes the password from the OS keychain
func DeletePassword(profile string) error {
	err := keyring.Delete(keyringName, profile)
	if err == keyring.ErrNotFound {
		return nil
	}
	return err
}
