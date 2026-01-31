package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/zkmkarlsruhe/filterdns-client/internal/config"
)

// Client communicates with the daemon
type Client struct {
	socketPath string
}

// NewClient creates a new daemon client
func NewClient() *Client {
	return &Client{socketPath: SocketPath}
}

// send sends a request to the daemon and returns the response
func (c *Client) send(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon: %w (is it running?)", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}

// Ping checks if the daemon is running
func (c *Client) Ping() error {
	resp, err := c.send(Request{Action: "ping"})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("ping failed: %s", resp.Error)
	}
	return nil
}

// IsRunning checks if the daemon is reachable
func (c *Client) IsRunning() bool {
	return c.Ping() == nil
}

// Enable starts DNS filtering
func (c *Client) Enable() (*Status, error) {
	resp, err := c.send(Request{Action: "enable"})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Status, nil
}

// Disable stops DNS filtering
func (c *Client) Disable() (*Status, error) {
	resp, err := c.send(Request{Action: "disable"})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Status, nil
}

// Status returns the current daemon status
func (c *Client) Status() (*Status, error) {
	resp, err := c.send(Request{Action: "status"})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Status, nil
}

// GetConfig returns the current configuration
func (c *Client) GetConfig() (*config.Config, error) {
	resp, err := c.send(Request{Action: "get_config"})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf(resp.Error)
	}
	return resp.Config, nil
}

// SetConfig updates the daemon configuration
func (c *Client) SetConfig(cfg *config.Config) error {
	resp, err := c.send(Request{Action: "set_config", Config: cfg})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf(resp.Error)
	}
	return nil
}
