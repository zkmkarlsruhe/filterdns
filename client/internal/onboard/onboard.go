// Package onboard handles web-based onboarding for the FilterDNS client.
//
// The onboarding flow:
// 1. Client calls /api/client/onboard/start to get a token
// 2. Client opens browser to /onboard?token=xxx
// 3. User selects/creates profile in browser
// 4. Browser calls /api/client/onboard/complete
// 5. Client polls /api/client/onboard/poll until completed
// 6. Client saves profile config
package onboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/zkm/filterdns-client/internal/config"
)

// Result contains the onboarding result
type Result struct {
	ProfileName string
	Password    string
	ServerURL   string
}

// StartOnboardingResponse from /api/client/onboard/start
type StartOnboardingResponse struct {
	Token      string `json:"token"`
	OnboardURL string `json:"onboard_url"`
	ExpiresAt  string `json:"expires_at"`
}

// PollResponse from /api/client/onboard/poll
type PollResponse struct {
	Completed bool             `json:"completed"`
	ExpiresAt string           `json:"expires_at,omitempty"`
	Profile   *ProfileInfo     `json:"profile,omitempty"`
	Password  string           `json:"password,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// ProfileInfo contains profile details
type ProfileInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	HasPassword bool   `json:"has_password"`
	DNSEndpoint string `json:"dns_endpoint"`
	DoHURL      string `json:"doh_url"`
}

// Run starts the web-based onboarding flow
func Run(serverURL string) (*Result, error) {
	// Step 1: Start onboarding session
	startResp, err := startOnboarding(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to start onboarding: %w", err)
	}

	// Step 2: Open browser (continue even if it fails)
	if err := openBrowser(startResp.OnboardURL); err != nil {
		fmt.Printf("\nCould not open browser automatically.\n")
		fmt.Printf("Please open this URL in your browser:\n\n")
		fmt.Printf("  %s\n\n", startResp.OnboardURL)
	} else {
		fmt.Println("Browser opened.")
	}

	fmt.Println("Complete the setup in your browser...")
	fmt.Println("Waiting for completion...")

	// Step 3: Poll for completion
	result, err := pollForCompletion(serverURL, startResp.Token)
	if err != nil {
		return nil, err
	}

	result.ServerURL = serverURL
	return result, nil
}

func startOnboarding(serverURL string) (*StartOnboardingResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Send empty JSON body (required by server)
	resp, err := client.Post(
		serverURL+"/api/client/onboard/start",
		"application/json",
		strings.NewReader("{}"),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var result StartOnboardingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

func pollForCompletion(serverURL, token string) (*Result, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	pollURL := fmt.Sprintf("%s/api/client/onboard/poll?token=%s", serverURL, url.QueryEscape(token))

	// Poll every 2 seconds for up to 10 minutes
	maxAttempts := 300
	for i := 0; i < maxAttempts; i++ {
		resp, err := client.Get(pollURL)
		if err != nil {
			// Network error, wait and retry
			time.Sleep(2 * time.Second)
			continue
		}

		var pollResp PollResponse
		if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
			resp.Body.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		resp.Body.Close()

		if pollResp.Error != "" {
			return nil, fmt.Errorf("onboarding error: %s", pollResp.Error)
		}

		if pollResp.Completed && pollResp.Profile != nil {
			return &Result{
				ProfileName: pollResp.Profile.Name,
				Password:    pollResp.Password,
			}, nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("onboarding timed out - please try again")
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		// Try xdg-open first, fall back to common browsers
		if _, err := exec.LookPath("xdg-open"); err == nil {
			cmd = exec.Command("xdg-open", url)
		} else if _, err := exec.LookPath("x-www-browser"); err == nil {
			cmd = exec.Command("x-www-browser", url)
		} else if _, err := exec.LookPath("firefox"); err == nil {
			cmd = exec.Command("firefox", url)
		} else if _, err := exec.LookPath("chromium"); err == nil {
			cmd = exec.Command("chromium", url)
		} else {
			return fmt.Errorf("no browser found - please open manually: %s", url)
		}
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported OS: %s - please open manually: %s", runtime.GOOS, url)
	}

	return cmd.Start()
}

// SaveResult saves the onboarding result to config
func SaveResult(result *Result) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	cfg.Profile = result.ProfileName
	if result.ServerURL != "" {
		cfg.ServerURL = result.ServerURL
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Save password if provided
	if result.Password != "" {
		if err := config.SetPassword(result.ProfileName, result.Password); err != nil {
			return fmt.Errorf("failed to save password: %w", err)
		}
	}

	return nil
}
