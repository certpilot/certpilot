// CertPilot Self-Signed Gateway
//
// A gateway plugin that issues self-signed certificates for development and
// testing. It exists to exercise the full core-to-gateway path without
// depending on a real CA, and should never be pointed at production traffic.
//
// Usage:
//
//	go run ./gateways/selfsigned/cmd/ --port=9091 --insecure
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/gateways/selfsigned"
)

func main() {
	port := flag.Int("port", 9091, "gRPC server port")

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

	provider := selfsigned.NewProvider()
	providerv1.RegisterCertificateProviderServiceServer(server, provider)

	slog.Info("starting CertPilot self-signed gateway", "port", *port, "mtls", !tlsCfg.Insecure)

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
