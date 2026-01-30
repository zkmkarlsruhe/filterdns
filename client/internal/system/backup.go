// Package system provides DNS backup/restore functionality.
//
// This file implements persistent DNS backup that survives crashes.
// The backup is stored in a JSON file, so even if the app is killed
// with SIGKILL or crashes, the original DNS settings can be restored.
package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// DNSBackup stores the original DNS settings before modification
type DNSBackup struct {
	// Timestamp when backup was created
	CreatedAt time.Time `json:"created_at"`

	// Platform-specific backup data
	Linux   *LinuxDNSBackup   `json:"linux,omitempty"`
	Darwin  *DarwinDNSBackup  `json:"darwin,omitempty"`
	Windows *WindowsDNSBackup `json:"windows,omitempty"`

	// Flag indicating DNS was modified by us
	DNSModified bool `json:"dns_modified"`
}

// LinuxDNSBackup stores Linux-specific DNS backup
type LinuxDNSBackup struct {
	// Which DNS system was in use
	System string `json:"system"` // "systemd-resolved", "networkmanager", "resolvconf"

	// For NetworkManager: original connection settings
	ConnectionName   string   `json:"connection_name,omitempty"`
	OriginalDNS      []string `json:"original_dns,omitempty"`
	IgnoreAutoDNS    bool     `json:"ignore_auto_dns,omitempty"`

	// For systemd-resolved: interface name
	Interface string `json:"interface,omitempty"`

	// For resolv.conf: we use file backup, but track that we modified it
	ResolvConfModified bool `json:"resolvconf_modified,omitempty"`
}

// DarwinDNSBackup stores macOS-specific DNS backup
type DarwinDNSBackup struct {
	// Map of network service name to original DNS servers
	Services map[string][]string `json:"services"`
}

// WindowsDNSBackup stores Windows-specific DNS backup
type WindowsDNSBackup struct {
	// Map of interface index to original DNS servers
	Interfaces map[int][]string `json:"interfaces"`
}

// backupFilePath returns the path to the backup file
func backupFilePath() string {
	var dir string

	switch runtime.GOOS {
	case "darwin":
		dir = "/Library/Application Support/FilterDNS"
	case "windows":
		dir = filepath.Join(os.Getenv("PROGRAMDATA"), "FilterDNS")
	default: // linux
		dir = "/var/lib/filterdns"
	}

	// Ensure directory exists
	os.MkdirAll(dir, 0755)

	return filepath.Join(dir, "dns-backup.json")
}

// SaveBackup persists the DNS backup to disk
func SaveBackup(backup *DNSBackup) error {
	backup.CreatedAt = time.Now()
	backup.DNSModified = true

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(backupFilePath(), data, 0644)
}

// LoadBackup loads the DNS backup from disk
func LoadBackup() (*DNSBackup, error) {
	data, err := os.ReadFile(backupFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No backup exists
		}
		return nil, err
	}

	var backup DNSBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, err
	}

	return &backup, nil
}

// ClearBackup removes the backup file (called after successful restore)
func ClearBackup() error {
	err := os.Remove(backupFilePath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// HasPendingRestore checks if there's a backup that needs to be restored
// (e.g., after a crash). Call this on startup.
func HasPendingRestore() bool {
	backup, err := LoadBackup()
	if err != nil || backup == nil {
		return false
	}
	return backup.DNSModified
}

// RestoreFromBackupIfNeeded checks for a pending backup and restores DNS.
// This should be called at startup to recover from crashes.
func RestoreFromBackupIfNeeded() error {
	if !HasPendingRestore() {
		return nil
	}

	// Attempt to restore
	if err := ResetDNS(); err != nil {
		return err
	}

	// Clear the backup file
	return ClearBackup()
}
