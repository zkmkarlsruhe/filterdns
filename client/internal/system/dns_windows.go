//go:build windows

package system

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// setDNS sets the system DNS server on Windows
func setDNS(server string) error {
	interfaces, err := getInterfaces()
	if err != nil {
		return err
	}

	// Create persistent backup before modifying
	backup := &DNSBackup{
		Windows: &WindowsDNSBackup{
			Interfaces: make(map[int][]string),
		},
	}

	for _, iface := range interfaces {
		// Get and store current DNS
		current, _ := getDNSForInterface(iface)
		if len(current) > 0 {
			backup.Windows.Interfaces[iface] = current
		}
	}

	// Save backup to disk BEFORE modifying DNS
	if err := SaveBackup(backup); err != nil {
		return fmt.Errorf("failed to save DNS backup: %w", err)
	}

	// Now modify DNS
	for _, iface := range interfaces {
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
			fmt.Sprintf("name=%d", iface),
			"source=static",
			fmt.Sprintf("address=%s", server),
			"validate=no")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set DNS for interface %d: %s: %w", iface, string(output), err)
		}
	}

	// Flush DNS cache
	exec.Command("ipconfig", "/flushdns").Run()

	return nil
}

// resetDNS restores the original system DNS settings on Windows
func resetDNS() error {
	// Load backup from disk
	backup, err := LoadBackup()
	if err != nil {
		return fmt.Errorf("failed to load DNS backup: %w", err)
	}

	interfaces, err := getInterfaces()
	if err != nil {
		return err
	}

	for _, iface := range interfaces {
		// Check if we have a backup for this interface
		if backup != nil && backup.Windows != nil {
			if original, ok := backup.Windows.Interfaces[iface]; ok && len(original) > 0 {
				// Restore original DNS
				cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
					fmt.Sprintf("name=%d", iface),
					"source=static",
					fmt.Sprintf("address=%s", original[0]),
					"validate=no")
				cmd.Run()

				// Add additional DNS servers
				for i := 1; i < len(original); i++ {
					cmd = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
						fmt.Sprintf("name=%d", iface),
						fmt.Sprintf("address=%s", original[i]),
						"validate=no")
					cmd.Run()
				}
			} else {
				// No backup for this interface, set to DHCP
				cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
					fmt.Sprintf("name=%d", iface),
					"source=dhcp")
				cmd.Run()
			}
		} else {
			// No backup at all, set to DHCP
			cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
				fmt.Sprintf("name=%d", iface),
				"source=dhcp")
			cmd.Run()
		}
	}

	// Clear backup file after successful restore
	ClearBackup()

	// Flush DNS cache
	exec.Command("ipconfig", "/flushdns").Run()

	return nil
}

// getCurrentDNS returns the current system DNS servers on Windows
func getCurrentDNS() ([]string, error) {
	interfaces, err := getInterfaces()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var servers []string

	for _, iface := range interfaces {
		dns, err := getDNSForInterface(iface)
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

// getInterfaces returns interface indices for active network adapters
func getInterfaces() ([]int, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var interfaces []int
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip disconnected interfaces
		if fields[3] != "connected" {
			continue
		}

		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		interfaces = append(interfaces, idx)
	}

	return interfaces, nil
}

// getDNSForInterface returns the DNS servers for a specific interface
func getDNSForInterface(iface int) ([]string, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers", fmt.Sprintf("name=%d", iface))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for IP addresses in the output
		if strings.Count(line, ".") == 3 && !strings.Contains(line, " ") {
			servers = append(servers, line)
		}
	}

	return servers, nil
}
