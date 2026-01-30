//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	resolvConf       = "/etc/resolv.conf"
	resolvConfBackup = "/etc/resolv.conf.filterdns.bak"
)

// setDNS sets the system DNS server on Linux
func setDNS(server string) error {
	// Detect which DNS management system is in use
	if isSystemdResolved() {
		return setDNSSystemdResolved(server)
	}

	if isNetworkManager() {
		return setDNSNetworkManager(server)
	}

	// Fallback: directly modify /etc/resolv.conf
	return setDNSResolvConf(server)
}

// resetDNS restores the original system DNS settings
func resetDNS() error {
	if isSystemdResolved() {
		return resetDNSSystemdResolved()
	}

	if isNetworkManager() {
		return resetDNSNetworkManager()
	}

	return resetDNSResolvConf()
}

// getCurrentDNS returns the current system DNS servers
func getCurrentDNS() ([]string, error) {
	file, err := os.Open(resolvConf)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			server := strings.TrimPrefix(line, "nameserver ")
			servers = append(servers, strings.TrimSpace(server))
		}
	}

	return servers, scanner.Err()
}

// isSystemdResolved checks if systemd-resolved is managing DNS
func isSystemdResolved() bool {
	// Check if /etc/resolv.conf is a symlink to systemd-resolved
	link, err := os.Readlink(resolvConf)
	if err != nil {
		return false
	}
	return strings.Contains(link, "systemd") || strings.Contains(link, "resolved")
}

// isNetworkManager checks if NetworkManager is managing DNS
func isNetworkManager() bool {
	_, err := exec.LookPath("nmcli")
	if err != nil {
		return false
	}

	// Check if NetworkManager is running
	cmd := exec.Command("systemctl", "is-active", "NetworkManager")
	output, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(output)) == "active"
}

// setDNSSystemdResolved configures DNS via systemd-resolved
func setDNSSystemdResolved(server string) error {
	// Get the default interface
	iface, err := getDefaultInterface()
	if err != nil {
		return fmt.Errorf("failed to get default interface: %w", err)
	}

	// Create persistent backup
	backup := &DNSBackup{
		Linux: &LinuxDNSBackup{
			System:    "systemd-resolved",
			Interface: iface,
		},
	}
	if err := SaveBackup(backup); err != nil {
		return fmt.Errorf("failed to save DNS backup: %w", err)
	}

	// Use resolvectl to set DNS for the interface
	cmd := exec.Command("resolvectl", "dns", iface, server)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl failed: %s: %w", string(output), err)
	}

	// Set this interface as the default route for DNS
	cmd = exec.Command("resolvectl", "default-route", iface, "true")
	cmd.Run() // Ignore errors, not all versions support this

	return nil
}

// resetDNSSystemdResolved restores DNS via systemd-resolved
func resetDNSSystemdResolved() error {
	// Load backup to get interface name
	backup, _ := LoadBackup()

	var iface string
	if backup != nil && backup.Linux != nil && backup.Linux.Interface != "" {
		iface = backup.Linux.Interface
	} else {
		var err error
		iface, err = getDefaultInterface()
		if err != nil {
			return err
		}
	}

	// Revert to DHCP-provided DNS
	cmd := exec.Command("resolvectl", "revert", iface)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl revert failed: %s: %w", string(output), err)
	}

	// Clear backup
	ClearBackup()

	return nil
}

// setDNSNetworkManager configures DNS via NetworkManager
func setDNSNetworkManager(server string) error {
	// Get the active connection
	cmd := exec.Command("nmcli", "-t", "-f", "NAME,DEVICE,STATE", "connection", "show", "--active")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get active connection: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("no active network connection")
	}

	// Parse the first active connection
	parts := strings.Split(lines[0], ":")
	if len(parts) < 1 {
		return fmt.Errorf("failed to parse connection info")
	}
	connName := parts[0]

	// Get current DNS settings for backup
	currentDNS, ignoreAutoDNS := getNetworkManagerDNS(connName)

	// Create persistent backup BEFORE modifying
	backup := &DNSBackup{
		Linux: &LinuxDNSBackup{
			System:           "networkmanager",
			ConnectionName:   connName,
			OriginalDNS:      currentDNS,
			IgnoreAutoDNS:    ignoreAutoDNS,
		},
	}
	if err := SaveBackup(backup); err != nil {
		return fmt.Errorf("failed to save DNS backup: %w", err)
	}

	// Set DNS for the connection
	cmd = exec.Command("nmcli", "connection", "modify", connName,
		"ipv4.dns", server,
		"ipv4.ignore-auto-dns", "yes")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nmcli modify failed: %s: %w", string(output), err)
	}

	// Reactivate the connection
	cmd = exec.Command("nmcli", "connection", "up", connName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nmcli up failed: %s: %w", string(output), err)
	}

	return nil
}

// getNetworkManagerDNS gets current DNS settings for a connection
func getNetworkManagerDNS(connName string) (dns []string, ignoreAuto bool) {
	// Get DNS servers
	cmd := exec.Command("nmcli", "-t", "-f", "ipv4.dns", "connection", "show", connName)
	output, err := cmd.Output()
	if err == nil {
		line := strings.TrimSpace(string(output))
		if strings.HasPrefix(line, "ipv4.dns:") {
			dnsStr := strings.TrimPrefix(line, "ipv4.dns:")
			if dnsStr != "" && dnsStr != "--" {
				dns = strings.Split(dnsStr, ",")
			}
		}
	}

	// Get ignore-auto-dns setting
	cmd = exec.Command("nmcli", "-t", "-f", "ipv4.ignore-auto-dns", "connection", "show", connName)
	output, err = cmd.Output()
	if err == nil {
		line := strings.TrimSpace(string(output))
		if strings.Contains(line, "yes") {
			ignoreAuto = true
		}
	}

	return dns, ignoreAuto
}

// resetDNSNetworkManager restores DNS via NetworkManager
func resetDNSNetworkManager() error {
	// Load backup
	backup, err := LoadBackup()
	if err != nil {
		return fmt.Errorf("failed to load DNS backup: %w", err)
	}

	var connName string
	var originalDNS []string
	var ignoreAutoDNS bool

	if backup != nil && backup.Linux != nil {
		connName = backup.Linux.ConnectionName
		originalDNS = backup.Linux.OriginalDNS
		ignoreAutoDNS = backup.Linux.IgnoreAutoDNS
	}

	// If no backup, get current active connection
	if connName == "" {
		cmd := exec.Command("nmcli", "-t", "-f", "NAME", "connection", "show", "--active")
		output, err := cmd.Output()
		if err != nil {
			ClearBackup()
			return nil
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) == 0 {
			ClearBackup()
			return nil
		}
		connName = lines[0]
	}

	// Restore original settings
	var dnsValue string
	var ignoreAutoValue string

	if len(originalDNS) > 0 {
		// Restore original static DNS
		dnsValue = strings.Join(originalDNS, ",")
		if ignoreAutoDNS {
			ignoreAutoValue = "yes"
		} else {
			ignoreAutoValue = "no"
		}
	} else {
		// No original DNS, restore to auto (DHCP)
		dnsValue = ""
		ignoreAutoValue = "no"
	}

	cmd := exec.Command("nmcli", "connection", "modify", connName,
		"ipv4.dns", dnsValue,
		"ipv4.ignore-auto-dns", ignoreAutoValue)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nmcli modify failed: %s: %w", string(output), err)
	}

	// Reactivate
	cmd = exec.Command("nmcli", "connection", "up", connName)
	cmd.Run()

	// Clear backup
	ClearBackup()

	return nil
}

// setDNSResolvConf directly modifies /etc/resolv.conf
func setDNSResolvConf(server string) error {
	// Backup the original file (only if no backup exists)
	if _, err := os.Stat(resolvConfBackup); os.IsNotExist(err) {
		input, err := os.ReadFile(resolvConf)
		if err != nil {
			return fmt.Errorf("failed to read resolv.conf: %w", err)
		}
		if err := os.WriteFile(resolvConfBackup, input, 0644); err != nil {
			return fmt.Errorf("failed to backup resolv.conf: %w", err)
		}
	}

	// Also create JSON backup for consistency
	backup := &DNSBackup{
		Linux: &LinuxDNSBackup{
			System:             "resolvconf",
			ResolvConfModified: true,
		},
	}
	SaveBackup(backup)

	// Write new resolv.conf
	content := fmt.Sprintf("# Generated by FilterDNS Client\nnameserver %s\n", server)
	if err := os.WriteFile(resolvConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	return nil
}

// resetDNSResolvConf restores the original /etc/resolv.conf
func resetDNSResolvConf() error {
	if _, err := os.Stat(resolvConfBackup); os.IsNotExist(err) {
		ClearBackup()
		return nil // No backup to restore
	}

	input, err := os.ReadFile(resolvConfBackup)
	if err != nil {
		return err
	}

	if err := os.WriteFile(resolvConf, input, 0644); err != nil {
		return err
	}

	os.Remove(resolvConfBackup)
	ClearBackup()
	return nil
}

// getDefaultInterface returns the name of the default network interface
func getDefaultInterface() (string, error) {
	// Parse /proc/net/route to find default gateway interface
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}

	// Fallback: try common interface names
	for _, name := range []string{"eth0", "wlan0", "enp0s3", "ens33"} {
		if _, err := os.Stat(filepath.Join("/sys/class/net", name)); err == nil {
			return name, nil
		}
	}

	return "", fmt.Errorf("no default interface found")
}
