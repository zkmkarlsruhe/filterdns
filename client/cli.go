package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/zkm/filterdns-client/internal/config"
	"github.com/zkm/filterdns-client/internal/daemon"
	"github.com/zkm/filterdns-client/internal/onboard"
	"github.com/zkm/filterdns-client/internal/service"
	"github.com/zkm/filterdns-client/internal/system"
)

func runCLI() {
	rootCmd := &cobra.Command{
		Use:   "filterdns-client",
		Short: "FilterDNS desktop client",
		Long:  "A DNS filtering client that connects to your FilterDNS server",
	}

	// Start command - enable DNS filtering via daemon
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start DNS filtering (via daemon)",
		Run: func(cmd *cobra.Command, args []string) {
			client := daemon.NewClient()
			if !client.IsRunning() {
				fmt.Fprintln(os.Stderr, "Daemon not running. Start with: sudo systemctl start filterdns")
				os.Exit(1)
			}

			status, err := client.Enable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("DNS filtering enabled for profile: %s\n", status.Profile)
		},
	}

	// Stop command - disable DNS filtering via daemon
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop DNS filtering (via daemon)",
		Run: func(cmd *cobra.Command, args []string) {
			client := daemon.NewClient()
			if !client.IsRunning() {
				fmt.Fprintln(os.Stderr, "Daemon not running.")
				os.Exit(1)
			}

			_, err := client.Disable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("DNS filtering disabled.")
		},
	}

	// Status command - show status from daemon
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current status",
		Run: func(cmd *cobra.Command, args []string) {
			client := daemon.NewClient()

			// Show config
			cfg, _ := config.Load()
			fmt.Printf("Profile:    %s\n", cfg.Profile)
			fmt.Printf("Server:     %s\n", cfg.ServerURL)

			// Show daemon status
			if !client.IsRunning() {
				fmt.Println("Daemon:     not running")
				return
			}

			status, err := client.Status()
			if err != nil {
				fmt.Printf("Daemon:     error (%v)\n", err)
				return
			}

			if status.Running {
				fmt.Printf("Filtering:  enabled (%d queries, %d blocked)\n", status.QueriesTotal, status.QueriesBlocked)
			} else {
				fmt.Println("Filtering:  disabled")
			}

			if len(cfg.Forwarders) > 0 {
				fmt.Println("Forwarders:")
				for _, f := range cfg.Forwarders {
					fmt.Printf("  %s → %s\n", f.Domain, f.Server)
				}
			}
		},
	}

	// Config command group
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	configSetCmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load()
			if err != nil {
				cfg = config.Default()
			}

			key, value := args[0], args[1]
			switch key {
			case "profile":
				cfg.Profile = value
			case "server":
				cfg.ServerURL = value
			case "password":
				if err := config.SetPassword(cfg.Profile, value); err != nil {
					fmt.Fprintf(os.Stderr, "Error storing password: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("Password stored securely.")
				return
			default:
				fmt.Fprintf(os.Stderr, "Unknown config key: %s\n", key)
				os.Exit(1)
			}

			if err := config.Save(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Set %s = %s\n", key, value)
		},
	}

	configShowCmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Profile:   %s\n", cfg.Profile)
			fmt.Printf("Server:    %s\n", cfg.ServerURL)
			fmt.Printf("Autostart: %v\n", cfg.Autostart)
			if len(cfg.Forwarders) > 0 {
				fmt.Println("Forwarders:")
				for _, f := range cfg.Forwarders {
					fmt.Printf("  %s → %s\n", f.Domain, f.Server)
				}
			}
		},
	}

	// Forwarder commands for split DNS
	forwarderCmd := &cobra.Command{
		Use:   "forwarder",
		Short: "Manage DNS forwarders (split DNS)",
	}

	forwarderAddCmd := &cobra.Command{
		Use:   "add <domain> <server>",
		Short: "Add a forwarder (e.g., 'add ts.net 100.100.100.100')",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load()
			if err != nil {
				cfg = config.Default()
			}

			cfg.Forwarders = append(cfg.Forwarders, config.Forwarder{
				Domain: args[0],
				Server: args[1],
			})

			if err := config.Save(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Added forwarder: %s → %s\n", args[0], args[1])
		},
	}

	forwarderListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all forwarders",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, _ := config.Load()
			if len(cfg.Forwarders) == 0 {
				fmt.Println("No forwarders configured.")
				return
			}
			for _, f := range cfg.Forwarders {
				fmt.Printf("%s → %s\n", f.Domain, f.Server)
			}
		},
	}

	forwarderRemoveCmd := &cobra.Command{
		Use:   "remove <domain>",
		Short: "Remove a forwarder",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}

			domain := args[0]
			newForwarders := make([]config.Forwarder, 0)
			found := false
			for _, f := range cfg.Forwarders {
				if f.Domain != domain {
					newForwarders = append(newForwarders, f)
				} else {
					found = true
				}
			}

			if !found {
				fmt.Fprintf(os.Stderr, "Forwarder not found: %s\n", domain)
				os.Exit(1)
			}

			cfg.Forwarders = newForwarders
			if err := config.Save(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Removed forwarder: %s\n", domain)
		},
	}

	// Install command - install as system service
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a system service (requires root)",
		Run: func(cmd *cobra.Command, args []string) {
			if os.Geteuid() != 0 {
				fmt.Fprintln(os.Stderr, "This command requires root privileges. Run with sudo.")
				os.Exit(1)
			}
			if err := service.Install(); err != nil {
				fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Uninstall command - remove system service
	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the system service (requires root)",
		Run: func(cmd *cobra.Command, args []string) {
			if os.Geteuid() != 0 {
				fmt.Fprintln(os.Stderr, "This command requires root privileges. Run with sudo.")
				os.Exit(1)
			}
			if err := service.Uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Daemon command - run the daemon (used by systemd service)
	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the daemon (used by system service)",
		Run: func(cmd *cobra.Command, args []string) {
			d := daemon.New()
			if err := d.Run(); err != nil {
				log.Fatalf("Daemon failed: %v", err)
			}
		},
	}

	// Service control commands
	serviceStartCmd := &cobra.Command{
		Use:   "service-start",
		Short: "Start the system service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := service.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to start service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service started")
		},
	}

	serviceStopCmd := &cobra.Command{
		Use:   "service-stop",
		Short: "Stop the system service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := service.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to stop service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service stopped")
		},
	}

	// DNS reset command - used by systemd ExecStopPost to restore DNS on service stop
	dnsResetCmd := &cobra.Command{
		Use:   "dns-reset",
		Short: "Reset system DNS to default (used by service on stop)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := system.ResetDNS(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to reset DNS: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("DNS settings restored")
		},
	}

	// Onboard command - web-based setup
	var onboardServer string
	onboardCmd := &cobra.Command{
		Use:   "onboard",
		Short: "Connect to FilterDNS via web-based setup",
		Long: `Opens a browser to complete the FilterDNS setup.

This launches a web-based onboarding flow where you can:
- Select an existing profile
- Create a new profile
- Configure your connection

The configuration is automatically saved when complete.`,
		Run: func(cmd *cobra.Command, args []string) {
			serverURL := onboardServer
			if serverURL == "" {
				// Try to get from existing config
				cfg, _ := config.Load()
				if cfg.ServerURL != "" {
					serverURL = cfg.ServerURL
				} else {
					serverURL = config.DefaultServerURL
				}
			}

			fmt.Printf("Connecting to %s...\n", serverURL)

			result, err := onboard.Run(serverURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Onboarding failed: %v\n", err)
				os.Exit(1)
			}

			if err := onboard.SaveResult(result); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("\nSuccess! Connected to profile: %s\n", result.ProfileName)
			fmt.Println("\nTo start filtering, run: filterdns-client start")
			fmt.Println("Or start the GUI app for system tray access.")
		},
	}
	onboardCmd.Flags().StringVarP(&onboardServer, "server", "s", "", "FilterDNS server URL (default: from config or http://localhost:8080)")

	// Build command tree
	configCmd.AddCommand(configSetCmd, configShowCmd)
	forwarderCmd.AddCommand(forwarderAddCmd, forwarderListCmd, forwarderRemoveCmd)
	rootCmd.AddCommand(startCmd, stopCmd, statusCmd, configCmd, forwarderCmd, onboardCmd)
	rootCmd.AddCommand(installCmd, uninstallCmd, daemonCmd)
	rootCmd.AddCommand(serviceStartCmd, serviceStopCmd, dnsResetCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
