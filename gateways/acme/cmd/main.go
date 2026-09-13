// CertPilot ACME Gateway
//
// A gateway plugin implementing RFC 8555 ACME for Let's Encrypt, ZeroSSL,
// BuyPass, Google Trust Services, Smallstep, and any other conforming CA.
//
// Usage:
//
//	go run ./gateways/acme/cmd/ \
//	    --port=9092 \
//	    --directory=letsencrypt-staging \
//	    --state-dir=./.certpilot/acme \
//	    --tls-cert=./.certpilot/pki/gateway.pem \
//	    --tls-key=./.certpilot/pki/gateway-key.pem \
//	    --tls-ca=./.certpilot/pki/ca.pem
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/certpilot/certpilot-gateway-sdk/grpckit"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/gateways/acme"
)

func main() {
	port := flag.Int("port", 9092, "gRPC server port")
	directory := flag.String("directory", "letsencrypt-staging",
		"default ACME directory URL, or an alias: letsencrypt, letsencrypt-staging, zerossl, buypass, google")
	stateDir := flag.String("state-dir", "",
		"directory for persisted ACME account keys; strongly recommended, as without it a new ACME account is registered after every restart")
	http01Addr := flag.String("http01-addr", ":80",
		"bind address for the http-01 challenge listener")

	tlsCert := flag.String("tls-cert", "", "path to this gateway's TLS certificate")
	tlsKey := flag.String("tls-key", "", "path to this gateway's TLS private key")
	tlsCA := flag.String("tls-ca", "", "path to the CA bundle used to verify the core")
	tlsInsecure := flag.Bool("insecure", false,
		"serve gRPC without TLS — development only; anyone who can reach the port can request certificates")
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

	if *stateDir == "" {
		slog.Warn("no --state-dir configured; ACME account keys will not survive a restart, " +
			"which will register a new account with the CA each time and can hit account rate limits")
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

	provider := acme.NewProvider(acme.Options{
		DefaultDirectory: *directory,
		StateDir:         *stateDir,
		HTTP01Addr:       *http01Addr,
	})
	providerv1.RegisterCertificateProviderServiceServer(server, provider)

	slog.Info("starting CertPilot ACME gateway",
		"port", *port,
		"default_directory", *directory,
		"state_dir", *stateDir,
		"mtls", !tlsCfg.Insecure,
	)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		server.GracefulStop()
	}()

	if err := grpckit.Serve(server, *port); err != nil {
		slog.Error("ACME gateway failed", "error", err)
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
