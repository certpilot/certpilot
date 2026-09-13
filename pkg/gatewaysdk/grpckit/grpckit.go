// Package grpckit provides gRPC transport setup shared by the CertPilot core
// and its gateway plugins.
//
// The core-to-gateway channel carries certificate signing requests, private
// keys, and CA account credentials. It is therefore mutually authenticated by
// default: both ends present a certificate, and both verify the other against a
// shared CA. Running it unauthenticated is possible but has to be asked for
// explicitly, and says so in the logs every time.
package grpckit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// TLSConfig describes the mutual TLS material for one end of the channel.
type TLSConfig struct {
	// CertFile and KeyFile are this process's own identity.
	CertFile string
	// KeyFile is the private key for CertFile.
	KeyFile string
	// CAFile is the CA bundle used to verify the peer.
	CAFile string
	// ServerName overrides the name a client expects in the gateway's
	// certificate. Needed when connecting by IP or through a service alias.
	ServerName string

	// Insecure disables TLS entirely. This is a deliberate escape hatch for
	// local development against a loopback address, and is never appropriate
	// for a channel that leaves the host.
	Insecure bool
}

// Enabled reports whether TLS material has been supplied.
func (t TLSConfig) Enabled() bool {
	return !t.Insecure && t.CertFile != "" && t.KeyFile != ""
}

// Validate checks that the configuration is coherent before anything binds a
// port, so a misconfiguration fails at startup rather than at first use.
func (t TLSConfig) Validate() error {
	if t.Insecure {
		if t.CertFile != "" || t.KeyFile != "" || t.CAFile != "" {
			return fmt.Errorf("grpckit: insecure mode was requested but TLS files were also supplied; pick one")
		}
		return nil
	}

	if t.CertFile == "" || t.KeyFile == "" {
		return fmt.Errorf("grpckit: cert and key are required (or set insecure explicitly for local development)")
	}
	if t.CAFile == "" {
		return fmt.Errorf("grpckit: a CA bundle is required to verify the peer")
	}

	for name, path := range map[string]string{"cert": t.CertFile, "key": t.KeyFile, "ca": t.CAFile} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("grpckit: %s file %s is not readable: %w", name, path, err)
		}
	}
	return nil
}

// ServerCredentials builds mutual-TLS transport credentials for a server.
func (t TLSConfig) ServerCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpckit: failed to load server keypair: %w", err)
	}

	pool, err := loadCAPool(t.CAFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		// The gateway holds the authority to issue certificates. An
		// unauthenticated caller must not be able to reach it.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}), nil
}

// ClientCredentials builds mutual-TLS transport credentials for a client.
func (t TLSConfig) ClientCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpckit: failed to load client keypair: %w", err)
	}

	pool, err := loadCAPool(t.CAFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   t.ServerName,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grpckit: failed to read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("grpckit: CA bundle %s contains no usable certificates", path)
	}
	return pool, nil
}

// ServerOptions configures a gRPC server.
type ServerOptions struct {
	Port           int
	MaxRecvMsgSize int
	// EnableReflection exposes the service schema to tools like grpcurl. It
	// makes a gateway trivially enumerable, so it defaults off and should stay
	// off outside development.
	EnableReflection bool
	TLS              TLSConfig
}

// DefaultServerOptions returns defaults suitable for production: reflection
// off, and TLS required.
func DefaultServerOptions() ServerOptions {
	return ServerOptions{
		Port:             9090,
		MaxRecvMsgSize:   10 * 1024 * 1024, // 10MB
		EnableReflection: false,
	}
}

// NewServer creates a gRPC server with standard configuration.
func NewServer(opts ServerOptions) (*grpc.Server, error) {
	if err := opts.TLS.Validate(); err != nil {
		return nil, err
	}

	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(opts.MaxRecvMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if opts.TLS.Insecure {
		slog.Warn("gRPC server is running WITHOUT TLS — anyone who can reach this port can request certificates from your CA. " +
			"This is acceptable only on a loopback address during development")
	} else {
		creds, err := opts.TLS.ServerCredentials()
		if err != nil {
			return nil, err
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}

	server := grpc.NewServer(serverOpts...)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	if opts.EnableReflection {
		slog.Warn("gRPC reflection is enabled; disable it outside development")
		reflection.Register(server)
	}

	return server, nil
}

// Serve starts the gRPC server on the configured port.
func Serve(server *grpc.Server, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("grpckit: failed to listen on port %d: %w", port, err)
	}

	slog.Info("gRPC server listening", "port", port)
	return server.Serve(lis)
}

// Dial connects to a gRPC server, mutually authenticating unless TLS was
// explicitly disabled.
func Dial(ctx context.Context, addr string, tlsCfg TLSConfig) (*grpc.ClientConn, error) {
	if err := tlsCfg.Validate(); err != nil {
		return nil, err
	}

	var creds credentials.TransportCredentials
	if tlsCfg.Insecure {
		slog.Warn("dialing gateway WITHOUT TLS", "addr", addr)
		creds = insecure.NewCredentials()
	} else {
		var err error
		creds, err = tlsCfg.ClientCredentials()
		if err != nil {
			return nil, err
		}
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("grpckit: failed to create client for %s: %w", addr, err)
	}

	// grpc.NewClient connects lazily. Force the handshake now so a bad
	// certificate or an unreachable gateway is reported at registration time
	// rather than during the first renewal.
	conn.Connect()
	if !waitForReady(ctx, conn) {
		conn.Close()
		return nil, fmt.Errorf("grpckit: could not establish a connection to %s: %w", addr, ctx.Err())
	}

	return conn, nil
}

func waitForReady(ctx context.Context, conn *grpc.ClientConn) bool {
	for {
		state := conn.GetState()
		if state.String() == "READY" {
			return true
		}
		if !conn.WaitForStateChange(ctx, state) {
			return false
		}
	}
}
