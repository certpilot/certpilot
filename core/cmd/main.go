// CertPilot Core Platform
//
// The central control plane for PKI management, automated certificate renewal,
// gateway plugin orchestration, and team collaboration.
//
// Usage:
//
//	go run ./core/cmd/ --config=config.dev.yaml
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	"github.com/certpilot/certpilot/core/server"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/secrets"
)

func main() {
	configPath := flag.String("config", "config.dev.yaml", "path to configuration YAML file")
	dbURLFlag := flag.String("db", "", "PostgreSQL database connection URL (or CERTPILOT_DB_URL env var)")
	generateKEK := flag.Bool("generate-kek", false,
		"print a new base64 key encryption key for CERTPILOT_KEK and exit")
	generateDevCerts := flag.String("generate-dev-certs", "",
		"write development mTLS material for the core-to-gateway channel into this directory and exit")
	migrate := flag.Bool("migrate", false,
		"apply outstanding database migrations and exit")
	migrationsDir := flag.String("migrations", "migrations",
		"directory holding the numbered .sql migration files")
	flag.Parse()

	// Setup subcommands run before anything else is initialized, so they work
	// on a machine with no config and no database.
	if *generateKEK {
		key, err := secrets.GenerateKEK()
		if err != nil {
			slog.Error("failed to generate key", "error", err)
			os.Exit(1)
		}
		fmt.Printf("CERTPILOT_KEK=%s\n", key)
		fmt.Fprintln(os.Stderr,
			"\nStore this in your secret manager. Certificate private keys and CA credentials\n"+
				"are encrypted with it; losing it makes every stored secret unrecoverable.")
		return
	}

	if *generateDevCerts != "" {
		paths, err := grpckit.GenerateDevPKI(*generateDevCerts, []string{"localhost", "127.0.0.1", "::1"})
		if err != nil {
			slog.Error("failed to generate development certificates", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote development mTLS material to %s\n\n", *generateDevCerts)
		fmt.Printf("  core:     %s / %s\n", paths.ClientCert, paths.ClientKey)
		fmt.Printf("  gateway:  %s / %s\n", paths.ServerCert, paths.ServerKey)
		fmt.Printf("  CA:       %s\n\n", paths.CACert)
		fmt.Fprintln(os.Stderr, "Development use only — the CA key is stored beside the certificates it signs.")
		return
	}

	if *migrate {
		if err := runMigrations(resolveDBURL(*dbURLFlag), *migrationsDir); err != nil {
			slog.Error("migration failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// Setup logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("initializing CertPilot Core", "config_file", *configPath)

	// Load configuration.
	cfg, err := config.LoadCoreConfig(*configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A config file that exists but is malformed or unsafe must not be
			// silently replaced by permissive defaults.
			slog.Error("configuration is invalid", "path", *configPath, "error", err)
			os.Exit(1)
		}

		slog.Warn("no configuration file found; starting with local development defaults",
			"path", *configPath)
		cfg = &config.CoreConfig{
			Server: config.ServerConfig{
				Host:           "127.0.0.1",
				Port:           8080,
				Mode:           "development",
				AllowedOrigins: []string{"http://localhost:3000"},
			},
			// A local administrator is created on first start and its
			// password printed once. There is no anonymous fallback: running
			// development as an unnamed superuser is what left the
			// authorisation paths untested and the audit log unattributable.
			Auth: config.AuthConfig{
				RoleClaim:       "certpilot_role",
				BootstrapAdmins: []string{"admin@certpilot.local"},
				Scopes:          []string{"openid", "profile", "email"},
			},
			Renewal: config.RenewalConfig{ScanInterval: 60, DefaultLeadDays: 30},
			Plugins: config.PluginsConfig{
				TLS: config.GatewayTLSConfig{Insecure: true},
				Gateways: []config.GatewayConfig{
					{Name: "selfsigned", Addr: "localhost:9091", Type: "selfsigned"},
				},
			},
		}
	}

	// Determine Database URL
	dbConnStr := resolveDBURL(*dbURLFlag)

	if dbConnStr == "" {
		slog.Info("no database connection string provided; using in-memory store with sample seed data")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := server.NewServer(ctx, cfg, dbConnStr)
	if err != nil {
		slog.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown handling
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received termination signal, initiating graceful shutdown", "signal", sig)

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("error during server shutdown", "error", err)
		}
		cancel()
	}()

	if err := srv.Start(); err != nil && err != http.ErrServerClosed {
		slog.Error("server encountered fatal error", "error", err)
		os.Exit(1)
	}

	slog.Info("CertPilot Core shutdown complete")
}

// resolveDBURL reads the connection string from, in order, the --db flag,
// CERTPILOT_DB_URL, and DATABASE_URL. An empty result means no database was
// configured, which is a supported local-development state rather than an error.
func resolveDBURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("CERTPILOT_DB_URL"); v != "" {
		return v
	}
	return os.Getenv("DATABASE_URL")
}

// runMigrations backs `--migrate`. It is a separate invocation rather than
// something the server does on startup so that a schema change is something an
// operator decides to run, not a side effect of a deploy restarting a replica.
func runMigrations(connStr, dir string) error {
	if connStr == "" {
		return fmt.Errorf("no database configured; pass --db or set CERTPILOT_DB_URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := store.Migrate(ctx, connStr, dir)
	if result != nil {
		for _, name := range result.Applied {
			fmt.Printf("  applied  %s\n", name)
		}
		for _, name := range result.Skipped {
			fmt.Printf("  already  %s\n", name)
		}
		for _, name := range result.Drifted {
			fmt.Fprintf(os.Stderr,
				"  WARNING  %s has changed since it was applied to this database.\n"+
					"           It was not rerun. Reconcile the difference with a new migration.\n", name)
		}
	}
	if err != nil {
		return err
	}

	if len(result.Applied) == 0 {
		fmt.Println("\nThe database schema is up to date.")
	} else {
		fmt.Printf("\nApplied %d migration(s).\n", len(result.Applied))
	}
	return nil
}
