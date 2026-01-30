package system

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/emersion/go-autostart"
)

const appName = "FilterDNS"

// SetAutostart enables or disables autostart on login
func SetAutostart(enabled bool) error {
	app := &autostart.App{
		Name:        appName,
		DisplayName: "FilterDNS Client",
		Exec:        getExecutablePath(),
	}

	if enabled {
		return app.Enable()
	}
	return app.Disable()
}

// IsAutostartEnabled checks if autostart is enabled
func IsAutostartEnabled() bool {
	app := &autostart.App{
		Name: appName,
	}
	return app.IsEnabled()
}

// getExecutablePath returns the path to the current executable
func getExecutablePath() []string {
	exe, err := os.Executable()
	if err != nil {
		// Fallback to common install locations
		switch runtime.GOOS {
		case "darwin":
			return []string{"/Applications/FilterDNS.app/Contents/MacOS/FilterDNS"}
		case "windows":
			return []string{filepath.Join(os.Getenv("PROGRAMFILES"), "FilterDNS", "filterdns-client.exe")}
		default:
			return []string{"/usr/bin/filterdns-client"}
		}
	}
	return []string{exe}
}
