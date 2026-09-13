// CertPilot Vault Gateway
//
// A gateway plugin that issues certificates from a HashiCorp Vault PKI secrets
// engine. Vault is the private CA most organisations running their own PKI
// already have, and unlike a public ACME CA it will describe itself: this
// gateway reports the mount's issuers so the CA that signs an estate is
// monitored alongside the certificates it signed.
//
// Usage:
//
//	go run ./gateways/vault/cmd/ --port=9093 --address=https://vault.internal:8200
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/gateways/vault"
)

func main() {
	port := flag.Int("port", 9093, "gRPC server port")

	address := flag.String("address", os.Getenv("VAULT_ADDR"),
		"default Vault address for accounts that do not name one, and the address HealthCheck probes")
	namespace := flag.String("namespace", os.Getenv("VAULT_NAMESPACE"),
		"default Vault Enterprise namespace")

	tlsCert := flag.String("tls-cert", "", "path to this gateway's TLS certificate")
	tlsKey := flag.String("tls-key", "", "path to this gateway's TLS private key")
	tlsCA := flag.String("tls-ca", "", "path to the CA bundle used to verify the core")
	tlsInsecure := flag.Bool("insecure", false, "serve gRPC without TLS — development only")
	reflection := flag.Bool("grpc-reflection", false, "enable gRPC reflection (development only)")

	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(*logLevel),
	})))

	tlsCfg := grpckit.TLSConfig{
		CertFile: *tlsCert,
		KeyFile:  *tlsKey,
		CAFile:   *tlsCA,
		Insecure: *tlsInsecure,
	}
	if err := tlsCfg.Validate(); err != nil {
		slog.Error("invalid TLS configuration", "error", err)
		slog.Info("generate development mTLS material with: make dev-certs")
		os.Exit(1)
	}

	opts := grpckit.DefaultServerOptions()
	opts.Port = *port
	opts.TLS = tlsCfg
	opts.EnableReflection = *reflection

	server, err := grpckit.NewServer(opts)
	if err != nil {
		slog.Error("failed to create gRPC server", "error", err)
		os.Exit(1)
	}

	// No Vault token is read from the environment here. A gateway that picked
	// up VAULT_TOKEN would issue with an ambient credential that no CA account
	// names, and nothing in CertPilot would record which identity signed.
	provider := vault.NewProvider(vault.Options{
		DefaultAddress:   *address,
		DefaultNamespace: *namespace,
	})
	providerv1.RegisterCertificateProviderServiceServer(server, provider)

	slog.Info("starting CertPilot Vault gateway",
		"port", *port, "mtls", !tlsCfg.Insecure, "default_address", *address)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		server.GracefulStop()
	}()

	if err := grpckit.Serve(server, *port); err != nil {
		slog.Error("gateway server failed", "error", err)
		os.Exit(1)
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
