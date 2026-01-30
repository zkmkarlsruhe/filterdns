package main

import (
	"log"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/driver/desktop"
	"github.com/zkm/filterdns-client/internal/gui"
)

func main() {
	// Check for CLI mode
	if len(os.Args) > 1 {
		runCLI()
		return
	}

	log.Println("Starting FilterDNS Client (GUI mode)")

	// Create Fyne application
	a := app.NewWithID("de.zkm.filterdns-client")
	a.SetIcon(gui.AppIcon())
	log.Println("Fyne app created")

	// Create main window
	w := a.NewWindow("FilterDNS")
	w.Resize(fyne.NewSize(400, 500))
	w.SetFixedSize(true)
	log.Println("Window created")

	// Create the GUI
	g := gui.New(a, w)
	w.SetContent(g.Content())
	log.Println("GUI initialized")

	// Setup system tray if supported
	if desk, ok := a.(desktop.App); ok {
		log.Println("Desktop app detected, setting up system tray...")
		g.SetupSystemTray(desk)
		log.Println("System tray setup complete")
	} else {
		log.Println("WARNING: Desktop features not available (no system tray)")
	}

	// Hide window on close (keep in tray)
	w.SetCloseIntercept(func() {
		log.Println("Window hidden (still running in tray)")
		w.Hide()
	})

	// Show window on start (don't hide to tray immediately)
	log.Println("Showing window...")
	w.Show()

	// Run the app
	log.Println("Running Fyne main loop...")
	a.Run()

	// Cleanup on exit
	log.Println("Shutting down...")
	g.Shutdown()
	log.Println("Goodbye")
}
