package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"text/template"
)

const systemdUnit = `[Unit]
Description=FilterDNS Client
After=network.target
Before=nss-lookup.target
Wants=nss-lookup.target

[Service]
Type=simple
ExecStart={{.ExecPath}} daemon
ExecStopPost={{.ExecPath}} dns-reset
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>de.zkm.filterdns-client</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.ExecPath}}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`

type Config struct {
	ExecPath string
}

// Install installs the service
func Install() error {
	switch runtime.GOOS {
	case "linux":
		return installLinux()
	case "darwin":
		return installDarwin()
	case "windows":
		return installWindows()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Uninstall removes the service
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallLinux()
	case "darwin":
		return uninstallDarwin()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Start starts the service
func Start() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("systemctl", "start", "filterdns-client")
	case "darwin":
		return runCmd("launchctl", "load", "/Library/LaunchDaemons/de.zkm.filterdns-client.plist")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Stop stops the service
func Stop() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("systemctl", "stop", "filterdns-client")
	case "darwin":
		return runCmd("launchctl", "unload", "/Library/LaunchDaemons/de.zkm.filterdns-client.plist")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Status returns the service status
func Status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "is-active", "filterdns-client").Output()
		if err != nil {
			return "not installed", nil
		}
		return string(out), nil
	case "darwin":
		out, err := exec.Command("launchctl", "list", "de.zkm.filterdns-client").Output()
		if err != nil {
			return "not installed", nil
		}
		return string(out), nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func installLinux() error {
	// Get current executable path
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Copy binary to /usr/bin
	destPath := "/usr/bin/filterdns-client"
	if exe != destPath {
		input, err := os.ReadFile(exe)
		if err != nil {
			return fmt.Errorf("failed to read binary: %w", err)
		}
		if err := os.WriteFile(destPath, input, 0755); err != nil {
			return fmt.Errorf("failed to copy binary to %s: %w", destPath, err)
		}
		fmt.Printf("Installed binary to %s\n", destPath)
	}

	// Create systemd unit file
	unitPath := "/etc/systemd/system/filterdns-client.service"
	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("failed to create unit file: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("unit").Parse(systemdUnit)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(f, Config{ExecPath: destPath}); err != nil {
		return fmt.Errorf("failed to write unit file: %w", err)
	}
	fmt.Printf("Created systemd unit at %s\n", unitPath)

	// Reload systemd and enable service
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCmd("systemctl", "enable", "filterdns-client"); err != nil {
		return err
	}

	fmt.Println("Service installed and enabled")
	fmt.Println("Start with: sudo systemctl start filterdns-client")
	return nil
}

func uninstallLinux() error {
	runCmd("systemctl", "stop", "filterdns-client")
	runCmd("systemctl", "disable", "filterdns-client")
	os.Remove("/etc/systemd/system/filterdns-client.service")
	runCmd("systemctl", "daemon-reload")
	os.Remove("/usr/bin/filterdns-client")
	fmt.Println("Service uninstalled")
	return nil
}

func installDarwin() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Copy binary to /usr/local/bin
	destPath := "/usr/local/bin/filterdns-client"
	if exe != destPath {
		input, err := os.ReadFile(exe)
		if err != nil {
			return fmt.Errorf("failed to read binary: %w", err)
		}
		if err := os.WriteFile(destPath, input, 0755); err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
		fmt.Printf("Installed binary to %s\n", destPath)
	}

	// Create launchd plist
	plistPath := "/Library/LaunchDaemons/de.zkm.filterdns-client.plist"
	f, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("failed to create plist: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("plist").Parse(launchdPlist)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(f, Config{ExecPath: destPath}); err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}
	fmt.Printf("Created launchd plist at %s\n", plistPath)

	fmt.Println("Service installed")
	fmt.Println("Start with: sudo launchctl load /Library/LaunchDaemons/de.zkm.filterdns-client.plist")
	return nil
}

func uninstallDarwin() error {
	runCmd("launchctl", "unload", "/Library/LaunchDaemons/de.zkm.filterdns-client.plist")
	os.Remove("/Library/LaunchDaemons/de.zkm.filterdns-client.plist")
	os.Remove("/usr/local/bin/filterdns-client")
	fmt.Println("Service uninstalled")
	return nil
}

func installWindows() error {
	return fmt.Errorf("Windows service installation not yet implemented")
}

func uninstallWindows() error {
	return fmt.Errorf("Windows service uninstallation not yet implemented")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
