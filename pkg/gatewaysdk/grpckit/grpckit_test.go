package grpckit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestGenerateDevPKI(t *testing.T) {
	dir := t.TempDir()

	paths, err := GenerateDevPKI(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}

	for _, p := range []string{paths.CACert, paths.ServerCert, paths.ServerKey, paths.ClientCert, paths.ClientKey} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	// Private keys must not be world-readable.
	for _, p := range []string{paths.ServerKey, paths.ClientKey, filepath.Join(dir, "ca-key.pem")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s has mode %o, want 600", p, perm)
		}
	}

	// The server certificate must chain to the CA and be valid for the hosts
	// the core will dial.
	caCert := readCert(t, paths.CACert)
	serverCert := readCert(t, paths.ServerCert)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("server certificate does not verify against the dev CA: %v", err)
	}
	if err := serverCert.VerifyHostname("localhost"); err != nil {
		t.Fatalf("server certificate is not valid for localhost: %v", err)
	}

	clientCert := readCert(t, paths.ClientCert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client certificate does not verify for client auth: %v", err)
	}
}

func TestGenerateDevPKIIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	first, err := GenerateDevPKI(dir, nil)
	if err != nil {
		t.Fatalf("first GenerateDevPKI: %v", err)
	}
	original, err := os.ReadFile(first.ServerCert)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if _, err := GenerateDevPKI(dir, nil); err != nil {
		t.Fatalf("second GenerateDevPKI: %v", err)
	}

	after, err := os.ReadFile(first.ServerCert)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(original) != string(after) {
		t.Fatal("re-running GenerateDevPKI replaced existing certificates")
	}
}

// The whole point of this package is that the channel is mutually
// authenticated, so prove a real client and server negotiate over it.
func TestMutualTLSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	paths, err := GenerateDevPKI(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}

	serverTLS := TLSConfig{CertFile: paths.ServerCert, KeyFile: paths.ServerKey, CAFile: paths.CACert}
	clientTLS := TLSConfig{CertFile: paths.ClientCert, KeyFile: paths.ClientKey, CAFile: paths.CACert, ServerName: "localhost"}

	server, addr := startTestServer(t, serverTLS)
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, addr, clientTLS)
	if err != nil {
		t.Fatalf("Dial over mTLS: %v", err)
	}
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check over mTLS: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("status = %v, want SERVING", resp.Status)
	}
}

// A client without a certificate must be refused: this is the property that
// stops anything that can reach the port from issuing certificates.
func TestServerRejectsClientWithoutCertificate(t *testing.T) {
	dir := t.TempDir()
	paths, err := GenerateDevPKI(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}

	server, addr := startTestServer(t, TLSConfig{
		CertFile: paths.ServerCert, KeyFile: paths.ServerKey, CAFile: paths.CACert,
	})
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// An insecure client speaks plaintext to a TLS listener and must not get a
	// working connection.
	conn, err := Dial(ctx, addr, TLSConfig{Insecure: true})
	if err == nil {
		defer conn.Close()
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer checkCancel()
		if _, err := healthpb.NewHealthClient(conn).Check(checkCtx, &healthpb.HealthCheckRequest{}); err == nil {
			t.Fatal("an unauthenticated client completed a health check against an mTLS server")
		}
	}
}

// A certificate from a different CA must not be accepted.
func TestServerRejectsForeignClientCertificate(t *testing.T) {
	trusted := t.TempDir()
	foreign := t.TempDir()

	trustedPaths, err := GenerateDevPKI(trusted, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}
	foreignPaths, err := GenerateDevPKI(foreign, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}

	server, addr := startTestServer(t, TLSConfig{
		CertFile: trustedPaths.ServerCert, KeyFile: trustedPaths.ServerKey, CAFile: trustedPaths.CACert,
	})
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Trust the real server, but present a client certificate from elsewhere.
	conn, err := Dial(ctx, addr, TLSConfig{
		CertFile:   foreignPaths.ClientCert,
		KeyFile:    foreignPaths.ClientKey,
		CAFile:     trustedPaths.CACert,
		ServerName: "localhost",
	})
	if err == nil {
		defer conn.Close()
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer checkCancel()
		if _, err := healthpb.NewHealthClient(conn).Check(checkCtx, &healthpb.HealthCheckRequest{}); err == nil {
			t.Fatal("a client certificate from an untrusted CA was accepted")
		}
	}
}

func TestTLSConfigValidate(t *testing.T) {
	dir := t.TempDir()
	paths, err := GenerateDevPKI(dir, nil)
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}

	cases := []struct {
		name    string
		cfg     TLSConfig
		wantErr bool
	}{
		{"complete", TLSConfig{CertFile: paths.ClientCert, KeyFile: paths.ClientKey, CAFile: paths.CACert}, false},
		{"explicitly insecure", TLSConfig{Insecure: true}, false},
		{"empty", TLSConfig{}, true},
		{"missing ca", TLSConfig{CertFile: paths.ClientCert, KeyFile: paths.ClientKey}, true},
		{"missing key", TLSConfig{CertFile: paths.ClientCert, CAFile: paths.CACert}, true},
		{"nonexistent file", TLSConfig{CertFile: filepath.Join(dir, "nope.pem"), KeyFile: paths.ClientKey, CAFile: paths.CACert}, true},
		{"insecure plus files", TLSConfig{Insecure: true, CertFile: paths.ClientCert}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewServerRejectsInvalidTLS(t *testing.T) {
	opts := DefaultServerOptions()
	opts.TLS = TLSConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem", CAFile: "/nonexistent/ca.pem"}

	if _, err := NewServer(opts); err == nil {
		t.Fatal("expected NewServer to reject unreadable TLS material")
	}
}

func TestDefaultServerOptionsAreSafe(t *testing.T) {
	opts := DefaultServerOptions()
	if opts.EnableReflection {
		t.Fatal("reflection should be off by default: it makes a gateway trivially enumerable")
	}
	if opts.TLS.Insecure {
		t.Fatal("TLS should not be disabled by default")
	}
}

func startTestServer(t *testing.T, tlsCfg TLSConfig) (*grpc.Server, string) {
	t.Helper()

	opts := DefaultServerOptions()
	opts.TLS = tlsCfg
	server, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() { _ = server.Serve(ln) }()

	return server, ln.Addr().String()
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s contains no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}
