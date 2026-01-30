package app

import (
	"sync"

	"github.com/zkm/filterdns-client/internal/config"
	"github.com/zkm/filterdns-client/internal/dns"
	"github.com/zkm/filterdns-client/internal/system"
)

// App holds the core application logic (shared between GUI and CLI)
type App struct {
	config  *config.Config
	proxy   *dns.Proxy
	running bool
	mu      sync.Mutex
}

// New creates a new App instance
func New() *App {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}
	return &App{
		config: cfg,
	}
}

// Config returns the current configuration
func (a *App) Config() *config.Config {
	return a.config
}

// IsRunning returns whether filtering is active
func (a *App) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// Enable starts DNS filtering
func (a *App) Enable() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return nil
	}

	a.proxy = dns.NewProxy(a.config)

	go func() {
		a.proxy.Start()
	}()

	if err := system.SetDNS("127.0.0.1"); err != nil {
		a.proxy.Stop()
		return err
	}

	a.running = true
	a.config.Enabled = true
	config.Save(a.config)

	return nil
}

// Disable stops DNS filtering
func (a *App) Disable() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return nil
	}

	if a.proxy != nil {
		a.proxy.Stop()
		a.proxy = nil
	}

	system.ResetDNS()

	a.running = false
	a.config.Enabled = false
	config.Save(a.config)

	return nil
}

// UpdateConfig updates the configuration
func (a *App) UpdateConfig(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	needsRestart := a.running && (cfg.Profile != a.config.Profile || cfg.ServerURL != a.config.ServerURL)

	a.config = cfg
	if err := config.Save(cfg); err != nil {
		return err
	}

	if needsRestart && a.proxy != nil {
		a.proxy.Stop()
		a.proxy = dns.NewProxy(a.config)
		go a.proxy.Start()
	}

	return nil
}

// UpdateForwarders updates the split DNS forwarders
func (a *App) UpdateForwarders(forwarders []config.Forwarder) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.config.Forwarders = forwarders
	config.Save(a.config)

	if a.proxy != nil {
		a.proxy.UpdateForwarders(forwarders)
	}
}
