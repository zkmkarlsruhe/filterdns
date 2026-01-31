// Package sync handles syncing profile state from the server.
//
// This allows the desktop client to reflect changes made in the web UI,
// such as pausing/resuming filtering.
package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/zkmkarlsruhe/filterdns-client/internal/config"
)

// SyncResponse from /api/client/sync/<profile>
type SyncResponse struct {
	Profile struct {
		ID               string  `json:"id"`
		Name             string  `json:"name"`
		FilteringEnabled bool    `json:"filtering_enabled"`
		PausedUntil      *string `json:"paused_until,omitempty"`
		MaintenanceMode  bool    `json:"maintenance_mode"`
		BlocklistCount   int     `json:"blocklist_count"`
	} `json:"profile"`
	DNS struct {
		Endpoint    string `json:"endpoint"`
		DoHURL      string `json:"doh_url"`
		DoTHostname string `json:"dot_hostname"`
	} `json:"dns"`
	ServerVersion string `json:"server_version"`
	SyncedAt      string `json:"synced_at"`
}

// StateCallback is called when the server state changes
type StateCallback func(enabled bool, pausedUntil *time.Time)

// Syncer periodically syncs with the server
type Syncer struct {
	serverURL   string
	profileName string
	interval    time.Duration
	callback    StateCallback

	lastState *SyncResponse
	mu        sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

// NewSyncer creates a new syncer
func NewSyncer(serverURL, profileName string, interval time.Duration, callback StateCallback) *Syncer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Syncer{
		serverURL:   serverURL,
		profileName: profileName,
		interval:    interval,
		callback:    callback,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start begins the sync loop
func (s *Syncer) Start() {
	go s.run()
}

// Stop stops the sync loop
func (s *Syncer) Stop() {
	s.cancel()
}

// GetLastState returns the last synced state
func (s *Syncer) GetLastState() *SyncResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastState
}

// SyncNow performs an immediate sync
func (s *Syncer) SyncNow() error {
	return s.doSync()
}

func (s *Syncer) run() {
	// Initial sync
	if err := s.doSync(); err != nil {
		log.Printf("Initial sync failed: %v", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.doSync(); err != nil {
				log.Printf("Sync failed: %v", err)
			}
		}
	}
}

func (s *Syncer) doSync() error {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/api/client/sync/%s", s.serverURL, s.profileName)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var syncResp SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check if state changed
	s.mu.Lock()
	stateChanged := s.lastState == nil ||
		s.lastState.Profile.FilteringEnabled != syncResp.Profile.FilteringEnabled ||
		s.lastState.Profile.PausedUntil != syncResp.Profile.PausedUntil
	s.lastState = &syncResp
	s.mu.Unlock()

	// Notify callback if state changed
	if stateChanged && s.callback != nil {
		var pausedUntil *time.Time
		if syncResp.Profile.PausedUntil != nil {
			t, err := time.Parse(time.RFC3339, *syncResp.Profile.PausedUntil)
			if err == nil {
				pausedUntil = &t
			}
		}
		s.callback(syncResp.Profile.FilteringEnabled, pausedUntil)
	}

	return nil
}

// SyncFromConfig creates a syncer from the current config
func SyncFromConfig(callback StateCallback) (*Syncer, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Profile == "" {
		return nil, fmt.Errorf("no profile configured")
	}

	return NewSyncer(cfg.ServerURL, cfg.Profile, 30*time.Second, callback), nil
}
