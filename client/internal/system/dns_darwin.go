//go:build darwin

package system

import (
	"fmt"
	"os/exec"
	"strings"
)

// setDNS sets the system DNS server on macOS
func setDNS(server string) error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}

	// Create persistent backup before modifying
	backup := &DNSBackup{
		Darwin: &DarwinDNSBackup{
			Services: make(map[string][]string),
		},
	}

	for _, service := range services {
		// Get and store current DNS
		current, _ := getDNSForService(service)
		if len(current) > 0 {
			backup.Darwin.Services[service] = current
		}
	}

	// Save backup to disk BEFORE modifying DNS
	if err := SaveBackup(backup); err != nil {
		return fmt.Errorf("failed to save DNS backup: %w", err)
	}

	// Now modify DNS
	for _, service := range services {
		cmd := exec.Command("networksetup", "-setdnsservers", service, server)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set DNS for %s: %s: %w", service, string(output), err)
		}
	}

	// Flush DNS cache
	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()

	return nil
}

// resetDNS restores the original system DNS settings on macOS
func resetDNS() error {
	// Load backup from disk
	backup, err := LoadBackup()
	if err != nil {
		return fmt.Errorf("failed to load DNS backup: %w", err)
	}

	services, err := listNetworkServices()
	if err != nil {
		return err
	}

	for _, service := range services {
		var args []string

		// Check if we have a backup for this service
		if backup != nil && backup.Darwin != nil {
			if original, ok := backup.Darwin.Services[service]; ok && len(original) > 0 {
				// Restore original DNS
				args = append([]string{"-setdnsservers", service}, original...)
			} else {
				// No backup for this service, set to DHCP
				args = []string{"-setdnsservers", service, "empty"}
			}
		} else {
			// No backup at all, set to DHCP
			args = []string{"-setdnsservers", service, "empty"}
		}

		cmd := exec.Command("networksetup", args...)
		cmd.Run() // Ignore errors for individual services
	}

	// Clear backup file after successful restore
	ClearBackup()

	// Flush DNS cache
	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()

	return nil
}

// getCurrentDNS returns the current system DNS servers on macOS
func getCurrentDNS() ([]string, error) {
	services, err := listNetworkServices()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var servers []string

	for _, service := range services {
		dns, err := getDNSForService(service)
		if err != nil {
			continue
		}
		for _, s := range dns {
			if !seen[s] {
				seen[s] = true
				servers = append(servers, s)
			}
		}
	}

	return servers, nil
}

// listNetworkServices returns all active network services
func listNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip header and disabled services (marked with *)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "denotes") {
			continue
		}
		services = append(services, line)
	}

	return services, nil
}

// getDNSForService returns the DNS servers for a specific network service
func getDNSForService(service string) ([]string, error) {
	cmd := exec.Command("networksetup", "-getdnsservers", service)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	result := strings.TrimSpace(string(output))
	if strings.Contains(result, "There aren't any DNS Servers") {
		return nil, nil
	}

	var servers []string
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			servers = append(servers, line)
		}
	}

	return servers, nil
}
