package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// Bootstrap DNS servers used to resolve the DoH server hostname
var bootstrapDNS = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
}

// DoHClient is a DNS-over-HTTPS client for FilterDNS
type DoHClient struct {
	serverURL  string
	profile    string
	httpClient *http.Client
	serverIP   string // Resolved IP of the DoH server
}

// NewDoHClient creates a new DoH client
func NewDoHClient(serverURL, profile string) *DoHClient {
	client := &DoHClient{
		serverURL: serverURL,
		profile:   profile,
	}

	// Resolve the DoH server's IP using bootstrap DNS
	client.resolveServerIP()

	// Create HTTP client with custom dialer that uses the resolved IP
	client.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: client.dialContext,
		},
	}

	return client
}

// resolveServerIP resolves the DoH server hostname using bootstrap DNS
func (c *DoHClient) resolveServerIP() {
	parsed, err := url.Parse(c.serverURL)
	if err != nil {
		return
	}

	hostname := parsed.Hostname()

	// Check if it's already an IP
	if ip := net.ParseIP(hostname); ip != nil {
		c.serverIP = ip.String()
		return
	}

	// Resolve using bootstrap DNS
	for _, bootstrap := range bootstrapDNS {
		ip, err := resolveWithDNS(hostname, bootstrap)
		if err == nil && ip != "" {
			c.serverIP = ip
			log.Printf("Resolved %s to %s using bootstrap DNS %s", hostname, ip, bootstrap)
			return
		}
	}

	log.Printf("Warning: Could not resolve %s using bootstrap DNS", hostname)
}

// resolveWithDNS resolves a hostname using a specific DNS server
func resolveWithDNS(hostname, dnsServer string) (string, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	resp, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return "", err
	}

	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found")
}

// dialContext is a custom dialer that uses the pre-resolved IP
func (c *DoHClient) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// If we have a resolved IP, use it
	if c.serverIP != "" {
		host, port, err := net.SplitHostPort(addr)
		if err == nil {
			parsed, _ := url.Parse(c.serverURL)
			if parsed != nil && host == parsed.Hostname() {
				addr = net.JoinHostPort(c.serverIP, port)
			}
		}
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// Query sends a DNS query over HTTPS
func (c *DoHClient) Query(ctx context.Context, msg *dns.Msg, password string) (*dns.Msg, error) {
	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Build the DoH URL
	// FilterDNS expects: /dns-query?profile=<name>
	url := fmt.Sprintf("%s/dns-query?dns=%s", c.serverURL, base64.RawURLEncoding.EncodeToString(packed))
	if c.profile != "" {
		url = fmt.Sprintf("%s&profile=%s", url, c.profile)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-message")

	// Add authentication if password is set
	if password != "" {
		req.Header.Set("X-FilterDNS-Password", password)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH server returned %d: %s", resp.StatusCode, string(body))
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack DNS response
	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// QueryPOST sends a DNS query via POST (for larger queries)
func (c *DoHClient) QueryPOST(ctx context.Context, msg *dns.Msg, password string) (*dns.Msg, error) {
	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Build the DoH URL
	url := fmt.Sprintf("%s/dns-query", c.serverURL)
	if c.profile != "" {
		url = fmt.Sprintf("%s?profile=%s", url, c.profile)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Add authentication if password is set
	if password != "" {
		req.Header.Set("X-FilterDNS-Password", password)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DoH server returned %d: %s", resp.StatusCode, string(body))
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack DNS response
	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return response, nil
}
