package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/zkmkarlsruhe/filterdns-client/internal/config"
	"github.com/zkmkarlsruhe/filterdns-client/internal/dns"
	"github.com/zkmkarlsruhe/filterdns-client/internal/system"
)

const SocketPath = "/var/run/filterdns.sock"

// Request represents a command from the client
type Request struct {
	Action string         `json:"action"`
	Config *config.Config `json:"config,omitempty"`
}

// Response represents the daemon's response
type Response struct {
	Success bool           `json:"success"`
	Error   string         `json:"error,omitempty"`
	Status  *Status        `json:"status,omitempty"`
	Config  *config.Config `json:"config,omitempty"`
}

// Status represents the current daemon status
type Status struct {
	Running        bool   `json:"running"`
	Profile        string `json:"profile"`
	ServerURL      string `json:"serverUrl"`
	QueriesTotal   int64  `json:"queriesTotal"`
	QueriesBlocked int64  `json:"queriesBlocked"`
}

// Daemon is the background service that handles DNS filtering
type Daemon struct {
	config   *config.Config
	proxy    *dns.Proxy
	listener net.Listener
	running  bool
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates a new daemon instance
func New() *Daemon {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Daemon{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Run starts the daemon
func (d *Daemon) Run() error {
	log.Println("Starting FilterDNS daemon...")

	// Check for crash recovery - restore DNS if we crashed while DNS was modified
	if err := system.RestoreFromBackupIfNeeded(); err != nil {
		log.Printf("Warning: crash recovery failed: %v", err)
	} else if system.HasPendingRestore() {
		log.Println("Recovered from previous crash - DNS settings restored")
	}

	// Remove old socket if exists
	os.Remove(SocketPath)

	// Create Unix socket
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	d.listener = listener

	// Make socket accessible to all users
	if err := os.Chmod(SocketPath, 0666); err != nil {
		log.Printf("Warning: failed to chmod socket: %v", err)
	}

	log.Printf("Listening on %s", SocketPath)

	// Auto-start DNS if was enabled
	if d.config.Enabled && d.config.Profile != "" {
		log.Println("Auto-starting DNS filtering (was enabled)...")
		if err := d.enable(); err != nil {
			log.Printf("Warning: auto-start failed: %v", err)
		}
	}

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down daemon...")
		d.Shutdown()
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go d.handleConnection(conn)
	}
}

// Shutdown stops the daemon
func (d *Daemon) Shutdown() {
	d.cancel()

	if d.running {
		d.disable()
	}

	if d.listener != nil {
		d.listener.Close()
	}

	os.Remove(SocketPath)
	log.Println("Daemon stopped")
}

// handleConnection processes a client connection
func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		encoder.Encode(Response{Success: false, Error: err.Error()})
		return
	}

	log.Printf("Received command: %s", req.Action)

	var resp Response

	switch req.Action {
	case "enable":
		if err := d.enable(); err != nil {
			resp = Response{Success: false, Error: err.Error()}
		} else {
			resp = Response{Success: true, Status: d.getStatus()}
		}

	case "disable":
		if err := d.disable(); err != nil {
			resp = Response{Success: false, Error: err.Error()}
		} else {
			resp = Response{Success: true, Status: d.getStatus()}
		}

	case "status":
		resp = Response{Success: true, Status: d.getStatus()}

	case "get_config":
		resp = Response{Success: true, Config: d.config}

	case "set_config":
		if req.Config != nil {
			if err := d.setConfig(req.Config); err != nil {
				resp = Response{Success: false, Error: err.Error()}
			} else {
				resp = Response{Success: true, Config: d.config}
			}
		} else {
			resp = Response{Success: false, Error: "no config provided"}
		}

	case "ping":
		resp = Response{Success: true}

	default:
		resp = Response{Success: false, Error: "unknown action"}
	}

	encoder.Encode(resp)
}

// enable starts DNS filtering
func (d *Daemon) enable() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	if d.config.Profile == "" {
		return fmt.Errorf("no profile configured")
	}

	log.Printf("Enabling DNS filtering for profile: %s", d.config.Profile)

	// Create and start proxy
	d.proxy = dns.NewProxy(d.config)

	go func() {
		if err := d.proxy.Start(); err != nil {
			log.Printf("DNS proxy error: %v", err)
		}
	}()

	// Configure system DNS
	if err := system.SetDNS("127.0.0.1"); err != nil {
		d.proxy.Stop()
		d.proxy = nil
		return fmt.Errorf("failed to set system DNS: %w", err)
	}

	d.running = true
	d.config.Enabled = true
	config.Save(d.config)

	log.Println("DNS filtering enabled")
	return nil
}

// disable stops DNS filtering
func (d *Daemon) disable() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return nil
	}

	log.Println("Disabling DNS filtering...")

	if d.proxy != nil {
		d.proxy.Stop()
		d.proxy = nil
	}

	system.ResetDNS()

	d.running = false
	d.config.Enabled = false
	config.Save(d.config)

	log.Println("DNS filtering disabled")
	return nil
}

// setConfig updates the configuration
func (d *Daemon) setConfig(cfg *config.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	needsRestart := d.running && (cfg.Profile != d.config.Profile || cfg.ServerURL != d.config.ServerURL)

	d.config = cfg
	if err := config.Save(cfg); err != nil {
		return err
	}

	if needsRestart {
		log.Println("Config changed, restarting proxy...")
		if d.proxy != nil {
			d.proxy.Stop()
		}
		d.proxy = dns.NewProxy(d.config)
		go d.proxy.Start()
	} else if d.proxy != nil {
		// Just update forwarders
		d.proxy.UpdateForwarders(cfg.Forwarders)
	}

	return nil
}

// getStatus returns the current status
func (d *Daemon) getStatus() *Status {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status := &Status{
		Running:   d.running,
		Profile:   d.config.Profile,
		ServerURL: d.config.ServerURL,
	}

	if d.proxy != nil {
		status.QueriesTotal, status.QueriesBlocked = d.proxy.GetStats()
	}

	return status
}
