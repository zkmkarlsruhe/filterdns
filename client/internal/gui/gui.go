package gui

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/zkmkarlsruhe/filterdns-client/internal/config"
	"github.com/zkmkarlsruhe/filterdns-client/internal/daemon"
	"github.com/zkmkarlsruhe/filterdns-client/internal/onboard"
	filtersync "github.com/zkmkarlsruhe/filterdns-client/internal/sync"
)

// GUI holds the application GUI state
type GUI struct {
	app    fyne.App
	window fyne.Window
	client *daemon.Client
	syncer *filtersync.Syncer

	// Local config copy for editing
	config *config.Config

	// Server state from sync
	serverFilteringEnabled bool
	serverPausedUntil      *time.Time

	// Widgets that need updating
	statusLabel     *widget.Label
	statusIcon      *widget.Icon
	toggleBtn       *widget.Button
	daemonStatus    *widget.Label
	profileEntry    *widget.Entry
	passwordEntry   *widget.Entry
	serverEntry     *widget.Entry
	autostartCheck  *widget.Check
	forwarderList   *fyne.Container
	serverSyncLabel *widget.Label
}

// New creates a new GUI instance
func New(app fyne.App, window fyne.Window) *GUI {
	// Load local config for editing
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}

	g := &GUI{
		app:                    app,
		window:                 window,
		client:                 daemon.NewClient(),
		config:                 cfg,
		serverFilteringEnabled: true,
	}

	// Start sync if profile is configured
	if cfg.Profile != "" {
		g.startSync()
	}

	return g
}

// startSync starts the server sync loop
func (g *GUI) startSync() {
	if g.syncer != nil {
		g.syncer.Stop()
	}

	syncer, err := filtersync.SyncFromConfig(g.onServerStateChanged)
	if err != nil {
		log.Printf("Failed to start sync: %v", err)
		return
	}

	g.syncer = syncer
	g.syncer.Start()
	log.Println("Server sync started")
}

// onServerStateChanged is called when the server state changes
func (g *GUI) onServerStateChanged(enabled bool, pausedUntil *time.Time) {
	g.serverFilteringEnabled = enabled
	g.serverPausedUntil = pausedUntil

	// Update UI on main thread
	if g.serverSyncLabel != nil {
		if !enabled && pausedUntil != nil {
			g.serverSyncLabel.SetText(fmt.Sprintf("Server: Paused until %s", pausedUntil.Format("15:04")))
		} else if !enabled {
			g.serverSyncLabel.SetText("Server: Filtering paused")
		} else {
			g.serverSyncLabel.SetText("Server: Filtering active")
		}
	}
}

// Content returns the main content container
func (g *GUI) Content() fyne.CanvasObject {
	// Daemon connection status
	g.daemonStatus = widget.NewLabel("Checking daemon...")
	g.daemonStatus.TextStyle = fyne.TextStyle{Italic: true}

	// Status section
	g.statusIcon = widget.NewIcon(theme.MediaStopIcon())
	g.statusLabel = widget.NewLabel("Unknown")
	g.statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	g.toggleBtn = widget.NewButton("Enable", g.toggle)
	g.toggleBtn.Importance = widget.HighImportance

	statusBox := container.NewHBox(
		g.statusIcon,
		g.statusLabel,
		layout.NewSpacer(),
		g.toggleBtn,
	)

	statusCard := widget.NewCard("Status", "", container.NewVBox(
		g.daemonStatus,
		statusBox,
	))

	// Profile section
	g.profileEntry = widget.NewEntry()
	g.profileEntry.SetPlaceHolder("my-profile-name")
	g.profileEntry.SetText(g.config.Profile)

	g.passwordEntry = widget.NewPasswordEntry()
	g.passwordEntry.SetPlaceHolder("Password (if protected)")
	if pwd, _ := config.GetPassword(g.config.Profile); pwd != "" {
		g.passwordEntry.SetText(pwd)
	}

	g.serverEntry = widget.NewEntry()
	g.serverEntry.SetPlaceHolder("https://filterdns.example.com")
	g.serverEntry.SetText(g.config.ServerURL)

	profileForm := container.NewVBox(
		widget.NewLabel("Profile Name"),
		g.profileEntry,
		widget.NewLabel("Password"),
		g.passwordEntry,
		widget.NewLabel("Server URL"),
		g.serverEntry,
	)

	profileCard := widget.NewCard("Profile", "", profileForm)

	// Forwarders section
	g.forwarderList = container.NewVBox()
	g.refreshForwarderList()

	addForwarderBtn := widget.NewButton("Add Forwarder", g.showAddForwarderDialog)
	addForwarderBtn.Importance = widget.MediumImportance

	tailscaleBtn := widget.NewButton("Add Tailscale", func() {
		g.addForwarder("ts.net", "100.100.100.100")
	})

	forwarderButtons := container.NewHBox(addForwarderBtn, tailscaleBtn)

	forwarderContent := container.NewVBox(
		widget.NewLabel("Forward specific domains to other DNS servers"),
		g.forwarderList,
		forwarderButtons,
	)

	forwarderCard := widget.NewCard("Split DNS", "For VPN/Tailscale compatibility", forwarderContent)

	// Settings section
	g.autostartCheck = widget.NewCheck("Start on login", g.onAutostartChanged)
	g.autostartCheck.Checked = g.config.Autostart

	dashboardBtn := widget.NewButton("Open Dashboard", g.openDashboard)

	settingsContent := container.NewVBox(
		g.autostartCheck,
		dashboardBtn,
	)

	settingsCard := widget.NewCard("Settings", "", settingsContent)

	// Save button
	saveBtn := widget.NewButton("Save", g.save)
	saveBtn.Importance = widget.HighImportance

	// Main layout
	content := container.NewVBox(
		statusCard,
		profileCard,
		forwarderCard,
		settingsCard,
		layout.NewSpacer(),
		saveBtn,
	)

	// Initial status check
	go g.refreshStatus()

	return container.NewPadded(content)
}

// SetupSystemTray configures the system tray icon and menu
func (g *GUI) SetupSystemTray(desk desktop.App) {
	log.Println("Setting up system tray...")

	// Build menu items
	menuItems := []*fyne.MenuItem{
		fyne.NewMenuItem("Show", func() {
			g.window.Show()
		}),
		fyne.NewMenuItemSeparator(),
	}

	// Add connect option if no profile configured
	if g.config.Profile == "" {
		menuItems = append(menuItems, fyne.NewMenuItem("Connect to FilterDNS", g.startOnboarding))
		menuItems = append(menuItems, fyne.NewMenuItemSeparator())
	} else {
		// Show profile name and enable/disable options
		menuItems = append(menuItems,
			fyne.NewMenuItem(fmt.Sprintf("Profile: %s", g.config.Profile), nil),
			fyne.NewMenuItem("Enable Filtering", func() {
				g.enable()
			}),
			fyne.NewMenuItem("Disable Filtering", func() {
				g.disable()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Open Dashboard", g.openDashboard),
			fyne.NewMenuItem("Change Profile...", g.startOnboarding),
			fyne.NewMenuItemSeparator(),
		)
	}

	menuItems = append(menuItems, fyne.NewMenuItem("Quit", func() {
		g.app.Quit()
	}))

	menu := fyne.NewMenu("FilterDNS", menuItems...)
	desk.SetSystemTrayMenu(menu)
	desk.SetSystemTrayIcon(AppIcon())
	log.Println("System tray setup complete")
}

// startOnboarding launches the web-based onboarding flow
func (g *GUI) startOnboarding() {
	log.Println("Starting onboarding...")

	serverURL := g.config.ServerURL
	if serverURL == "" {
		serverURL = config.DefaultServerURL
	}

	// Run onboarding in background
	go func() {
		result, err := onboard.Run(serverURL)
		if err != nil {
			log.Printf("Onboarding failed: %v", err)
			g.showError(fmt.Sprintf("Onboarding failed: %v", err))
			return
		}

		if err := onboard.SaveResult(result); err != nil {
			log.Printf("Failed to save config: %v", err)
			g.showError(fmt.Sprintf("Failed to save: %v", err))
			return
		}

		// Reload config
		cfg, _ := config.Load()
		g.config = cfg

		// Update UI
		if g.profileEntry != nil {
			g.profileEntry.SetText(cfg.Profile)
		}

		// Restart sync with new profile
		g.startSync()

		// Update daemon config
		if g.client.IsRunning() {
			g.client.SetConfig(cfg)
		}

		g.showInfo(fmt.Sprintf("Connected to profile: %s", result.ProfileName))
		log.Printf("Onboarding completed: %s", result.ProfileName)
	}()
}

// Shutdown cleans up resources
func (g *GUI) Shutdown() {
	// Stop syncer
	if g.syncer != nil {
		g.syncer.Stop()
	}
}

// refreshStatus updates the status from the daemon
func (g *GUI) refreshStatus() {
	if !g.client.IsRunning() {
		g.daemonStatus.SetText("⚠ Daemon not running (sudo systemctl start filterdns)")
		g.statusLabel.SetText("No daemon")
		g.statusIcon.SetResource(theme.ErrorIcon())
		g.toggleBtn.Disable()
		return
	}

	g.daemonStatus.SetText("✓ Connected to daemon")
	g.toggleBtn.Enable()

	status, err := g.client.Status()
	if err != nil {
		log.Printf("Failed to get status: %v", err)
		return
	}

	g.updateStatusDisplay(status)
}

// updateStatusDisplay updates the UI with status
func (g *GUI) updateStatusDisplay(status *daemon.Status) {
	if status.Running {
		g.statusLabel.SetText(fmt.Sprintf("Enabled (%d queries, %d blocked)", status.QueriesTotal, status.QueriesBlocked))
		g.statusIcon.SetResource(theme.MediaPlayIcon())
		g.toggleBtn.SetText("Disable")
		g.toggleBtn.Importance = widget.DangerImportance
	} else {
		g.statusLabel.SetText("Disabled")
		g.statusIcon.SetResource(theme.MediaStopIcon())
		g.toggleBtn.SetText("Enable")
		g.toggleBtn.Importance = widget.HighImportance
	}
	g.toggleBtn.Refresh()
}

// toggle enables or disables filtering
func (g *GUI) toggle() {
	status, err := g.client.Status()
	if err != nil {
		g.showError(fmt.Sprintf("Failed to get status: %v", err))
		return
	}

	if status.Running {
		g.disable()
	} else {
		g.enable()
	}
}

// enable starts DNS filtering via daemon
func (g *GUI) enable() {
	log.Println("Requesting enable from daemon...")
	status, err := g.client.Enable()
	if err != nil {
		log.Printf("Enable failed: %v", err)
		g.showError(fmt.Sprintf("Failed to enable: %v", err))
		return
	}
	g.updateStatusDisplay(status)
	g.showInfo("DNS filtering enabled")
}

// disable stops DNS filtering via daemon
func (g *GUI) disable() {
	log.Println("Requesting disable from daemon...")
	status, err := g.client.Disable()
	if err != nil {
		log.Printf("Disable failed: %v", err)
		g.showError(fmt.Sprintf("Failed to disable: %v", err))
		return
	}
	g.updateStatusDisplay(status)
	g.showInfo("DNS filtering disabled")
}

// save saves the configuration to the daemon
func (g *GUI) save() {
	g.config.Profile = g.profileEntry.Text
	g.config.ServerURL = g.serverEntry.Text

	// Save password to keyring (local)
	if g.passwordEntry.Text != "" {
		if err := config.SetPassword(g.config.Profile, g.passwordEntry.Text); err != nil {
			g.showError(fmt.Sprintf("Failed to save password: %v", err))
			return
		}
	}

	// Send config to daemon
	if g.client.IsRunning() {
		if err := g.client.SetConfig(g.config); err != nil {
			g.showError(fmt.Sprintf("Failed to update daemon: %v", err))
			return
		}
	}

	// Also save locally
	if err := config.Save(g.config); err != nil {
		g.showError(fmt.Sprintf("Failed to save config: %v", err))
		return
	}

	g.showInfo("Settings saved")
	g.refreshStatus()
}

// refreshForwarderList updates the forwarder list display
func (g *GUI) refreshForwarderList() {
	g.forwarderList.RemoveAll()

	if len(g.config.Forwarders) == 0 {
		g.forwarderList.Add(widget.NewLabel("No forwarders configured"))
		return
	}

	for _, fwd := range g.config.Forwarders {
		fwd := fwd // capture
		row := container.NewHBox(
			widget.NewLabel(fwd.Domain),
			widget.NewLabel("→"),
			widget.NewLabel(fwd.Server),
			layout.NewSpacer(),
			widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
				g.removeForwarder(fwd.Domain)
			}),
		)
		g.forwarderList.Add(row)
	}
}

// showAddForwarderDialog shows a dialog to add a new forwarder
func (g *GUI) showAddForwarderDialog() {
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("*.example.com")

	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("192.168.1.1")

	form := widget.NewForm(
		widget.NewFormItem("Domain", domainEntry),
		widget.NewFormItem("DNS Server", serverEntry),
	)

	dialog := widget.NewModalPopUp(
		container.NewVBox(
			widget.NewLabel("Add Split DNS Forwarder"),
			form,
			container.NewHBox(
				layout.NewSpacer(),
				widget.NewButton("Cancel", func() {}),
				widget.NewButton("Add", func() {
					if domainEntry.Text != "" && serverEntry.Text != "" {
						g.addForwarder(domainEntry.Text, serverEntry.Text)
					}
				}),
			),
		),
		g.window.Canvas(),
	)
	dialog.Show()
}

// addForwarder adds a new forwarder
func (g *GUI) addForwarder(domain, server string) {
	g.config.Forwarders = append(g.config.Forwarders, config.Forwarder{
		Domain: domain,
		Server: server,
	})
	g.refreshForwarderList()
}

// removeForwarder removes a forwarder
func (g *GUI) removeForwarder(domain string) {
	newForwarders := make([]config.Forwarder, 0)
	for _, f := range g.config.Forwarders {
		if f.Domain != domain {
			newForwarders = append(newForwarders, f)
		}
	}
	g.config.Forwarders = newForwarders
	g.refreshForwarderList()
}

// onAutostartChanged handles autostart checkbox changes
func (g *GUI) onAutostartChanged(checked bool) {
	g.config.Autostart = checked
}

// openDashboard opens the FilterDNS web dashboard
func (g *GUI) openDashboard() {
	dashURL := g.config.ServerURL
	if g.config.Profile != "" {
		dashURL = fmt.Sprintf("%s/profile/%s", g.config.ServerURL, g.config.Profile)
	}

	u, err := url.Parse(dashURL)
	if err != nil {
		return
	}

	g.app.OpenURL(u)
}

// showError displays an error notification
func (g *GUI) showError(msg string) {
	fyne.CurrentApp().SendNotification(&fyne.Notification{
		Title:   "FilterDNS Error",
		Content: msg,
	})
}

// showInfo displays an info notification
func (g *GUI) showInfo(msg string) {
	fyne.CurrentApp().SendNotification(&fyne.Notification{
		Title:   "FilterDNS",
		Content: msg,
	})
}
