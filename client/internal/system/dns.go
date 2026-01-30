package system

// SetDNS sets the system DNS server
// Implementation is platform-specific
func SetDNS(server string) error {
	return setDNS(server)
}

// ResetDNS restores the original system DNS settings
// Implementation is platform-specific
func ResetDNS() error {
	return resetDNS()
}

// GetCurrentDNS returns the current system DNS servers
// Implementation is platform-specific
func GetCurrentDNS() ([]string, error) {
	return getCurrentDNS()
}
