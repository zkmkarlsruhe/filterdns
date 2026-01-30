# FilterDNS Client

A desktop client for FilterDNS that manages your system DNS settings to route queries through your FilterDNS server.

## Features

- System tray application with quick enable/disable
- Automatic system DNS configuration (Linux, macOS, Windows)
- Split DNS support for VPN/Tailscale compatibility
- Secure password storage via OS keychain
- Auto-start on login

## Requirements

- Go 1.22+
- Node.js 18+
- Wails v2 (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)

### Platform-specific

**Linux:**
```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev
```

**macOS:**
- Xcode Command Line Tools

**Windows:**
- WebView2 Runtime (usually pre-installed on Windows 10/11)

## Development

```bash
# Install dependencies
make install-deps

# Run in development mode
make dev

# Build for current platform
make build
```

## Building Releases

```bash
# Build for all platforms
make build-all

# Or individually
make build-linux
make build-darwin
make build-windows
```

Built binaries are in `build/bin/`.

## CLI Usage

The client also supports CLI mode for scripting/automation:

```bash
# Configure profile
filterdns-client config set profile my-profile
filterdns-client config set server https://filterdns.example.com
filterdns-client config set password mysecretpassword

# Start/stop filtering
filterdns-client start
filterdns-client stop
filterdns-client status

# Split DNS for Tailscale
filterdns-client forwarder add ts.net 100.100.100.100
filterdns-client forwarder add internal.corp 10.0.0.53
filterdns-client forwarder list
filterdns-client forwarder remove ts.net
```

## Configuration

Config is stored in:
- Linux: `~/.config/FilterDNS/config.json`
- macOS: `~/Library/Application Support/FilterDNS/config.json`
- Windows: `%APPDATA%\FilterDNS\config.json`

Passwords are stored in the OS keychain (libsecret/Keychain/Credential Manager).

## How It Works

1. The client runs a local DNS proxy on `127.0.0.1:53`
2. System DNS is configured to use `127.0.0.1`
3. Queries are forwarded to FilterDNS via DNS-over-HTTPS
4. Split DNS rules route specific domains to other servers (e.g., Tailscale)

## Troubleshooting

### "Permission denied" on Linux
The client needs to bind to port 53. Either:
- Run with sudo (not recommended)
- Grant capability: `sudo setcap 'cap_net_bind_service=+ep' /path/to/filterdns-client`
- Use authbind or systemd socket activation

### DNS not working after crash
If the client crashes without resetting DNS:
```bash
filterdns-client stop  # Restores original DNS
```

### Tailscale/VPN not working
Add forwarders for VPN domains:
```bash
filterdns-client forwarder add ts.net 100.100.100.100
filterdns-client forwarder add *.internal 192.168.1.1
```

## License

MIT
