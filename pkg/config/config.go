// Package config provides configuration loading for CertPilot components.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CoreConfig is the main configuration for CertPilot Core.
type CoreConfig struct {
	Server  ServerConfig  `yaml:"server"`
	Auth    AuthConfig    `yaml:"auth"`
	Plugins PluginsConfig `yaml:"plugins"`
	PKI     PKIConfig     `yaml:"pki"`
	Renewal RenewalConfig `yaml:"renewal"`
	Logging LoggingConfig `yaml:"logging"`
	Secrets SecretsConfig `yaml:"secrets"`
	ACME    ACMEConfig    `yaml:"acme"`
}

// ACMEConfig controls the ACME server (RFC 8555), which lets certbot, acme.sh,
// win-acme and Caddy get certificates from CertPilot without the host agent.
//
// Off by default. It opens unauthenticated endpoints on the core's listener,
// so serving them is something an operator decides, not something an upgrade
// does.
type ACMEConfig struct {
	Enabled bool `yaml:"enabled"`
	// ExternalURL is the address clients reach this core on, such as
	// https://certpilot.example.com. Every URL the server hands out is built
	// from it, and a request is refused unless it was signed for one of them,
	// so it has to be what a client types. Required in production, where the
	// core is almost always behind something that changes the scheme or host.
	ExternalURL string `yaml:"external_url"`
	// Challenges is how HTTP-01 and DNS-01 are checked, for credentials that
	// require them. The defaults are what RFC 8555 says.
	Challenges ACMEChallengeConfig `yaml:"challenges"`
}

// ACMEChallengeConfig says where the core looks when it validates a challenge.
type ACMEChallengeConfig struct {
	// HTTPPort is the port HTTP-01 is fetched from. RFC 8555 says 80, and
	// production refuses anything else; another port is for a test harness.
	HTTPPort int `yaml:"http_port"`
	// DNSResolver is the host:port of the resolver used to look a name up,
	// for both challenges, or tcp://host:port to ask it over TCP only. Empty
	// uses the system's.
	DNSResolver string `yaml:"dns_resolver"`
}

// Port is the HTTP-01 port, 80 when unset.
func (c ACMEChallengeConfig) Port() int {
	if c.HTTPPort == 0 {
		return 80
	}
	return c.HTTPPort
}

// SecretsConfig says where the key encryption key comes from.
//
// The KEK is the one secret CertPilot cannot function without and cannot
// recover if it is lost: every certificate private key and CA credential in the
// database is sealed under it. Which is why where it lives is a deployment
// decision rather than a hard-coded one.
type SecretsConfig struct {
	// KEKProvider is "env" (the default), "file", or "vault".
	//
	// The default stays "env" because changing it would strand every existing
	// deployment on a restart — with the specific failure being that nothing
	// can be decrypted, which is the worst possible way to learn about a
	// configuration change.
	KEKProvider string `yaml:"kek_provider"`

	// KEKFile and KEKRetiredFiles are used when the provider is "file". This
	// is the shape every secret manager already speaks: a Docker secret, a
	// Kubernetes secret volume, a systemd credential and `vault agent`
	// templating all arrive as a file, and none of them need the value to pass
	// through the process environment on the way.
	KEKFile         string   `yaml:"kek_file"`
	KEKRetiredFiles []string `yaml:"kek_retired_files"`

	Vault VaultSecretsConfig `yaml:"vault"`
}

// VaultSecretsConfig reads the KEK from Vault's key/value store.
type VaultSecretsConfig struct {
	Address string `yaml:"address"`
	// Path is the full API path, e.g. "secret/data/certpilot/kek" for KV v2.
	// Both KV versions are handled without being told which.
	Path string `yaml:"path"`
	// Field defaults to "kek", RetiredField to "retired".
	Field        string `yaml:"field"`
	RetiredField string `yaml:"retired_field"`
	// TokenFile is preferred over an inline token: it is what an AppRole login,
	// `vault agent`, or a Kubernetes service account produces, and it can be
	// rotated under a running process. VAULT_TOKEN is read as a last resort,
	// for development.
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	Namespace string `yaml:"namespace"`
	// CACert verifies Vault's own certificate. Empty uses the system roots.
	CACert string `yaml:"ca_cert"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"` // development | production
	// AllowedOrigins lists the browser origins permitted to call the API.
	// A wildcard is rejected when credentials are in play, so this must name
	// the frontend explicitly.
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// IsProduction reports whether the server is running in production mode.
func (s ServerConfig) IsProduction() bool { return s.Mode == "production" }

// AuthConfig holds authentication settings.
//
// Two verification paths are supported. JWKSURL is the one to use: the core
// verifies asymmetrically signed tokens against the provider's published public
// keys and never holds anything capable of minting a token. JWTSecret is the
// legacy shared-secret path, which requires the core to hold a key that can
// forge admin tokens, and is kept only for providers that cannot issue
// asymmetrically signed tokens.
type AuthConfig struct {
	// JWKSURL is the JSON Web Key Set endpoint of the identity provider.
	JWKSURL string `yaml:"jwks_url"`
	// Issuer and Audience are validated when set.
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// JWTSecret enables legacy HS256 verification.
	JWTSecret string `yaml:"jwt_secret"`
	// RoleClaim names the claim inside app_metadata carrying the CertPilot
	// role. Defaults to "certpilot_role".
	RoleClaim string `yaml:"role_claim"`
	// AllowAnonymous is retained only so that setting it fails loudly.
	//
	// It used to treat a request with no Authorization header as admin, gated
	// to development mode on a loopback address. The gate held, but the
	// feature was still wrong: it meant every local session ran as an unnamed
	// superuser, so the authorisation paths were the least exercised code in
	// the system and the audit log attributed everything to a subject nobody
	// could be asked about. The uuid-subject defect fixed in migration 028
	// survived for precisely that reason.
	//
	// The field stays because silently ignoring it would be worse than
	// removing it: an operator who has this set believes their instance is
	// open and would not learn otherwise until somebody was refused.
	AllowAnonymous bool `yaml:"allow_anonymous"`

	// ClientID is the public client the browser authenticates as, using
	// authorization code with PKCE. There is deliberately no client secret: a
	// single-page application cannot keep one, and a secret shipped to a
	// browser is a secret published.
	//
	// The core serves this to the frontend from /auth/config rather than the
	// frontend carrying its own build-time copy. One instance is then
	// described by one file, and an operator cannot rebuild the UI against a
	// provider the API does not accept — a mismatch that presents as a
	// successful login followed by 401 on every request.
	ClientID string `yaml:"client_id"`

	// Scopes requested at authorization. openid is always sent; profile and
	// email are what populate a user's name and address here.
	Scopes []string `yaml:"scopes"`

	// RateLimitPerSecond and RateLimitBurst bound how fast one caller may make
	// requests. Zero means the built-in defaults; negative disables the limit,
	// which is a thing to do deliberately when something in front of the
	// application already shapes traffic.
	RateLimitPerSecond float64 `yaml:"rate_limit_per_second"`
	RateLimitBurst     float64 `yaml:"rate_limit_burst"`

	// BootstrapAdmins are email addresses promoted to admin the first time
	// they sign in.
	//
	// Somebody has to be able to grant the first role, and every alternative
	// is worse. "First sign-in wins" hands the estate to whoever reaches the
	// URL first, which on an instance that is reachable before it is announced
	// is not necessarily anyone you know. Naming the addresses makes the grant
	// deliberate, reviewable in the same file as everything else, and safe to
	// leave in place: it is matched only when the user has no row yet, so it
	// cannot silently restore an admin somebody deliberately demoted.
	BootstrapAdmins []string `yaml:"bootstrap_admins"`
}

// PluginsConfig holds gateway plugin settings.
type PluginsConfig struct {
	DiscoveryMode string          `yaml:"discovery_mode"` // static | docker | kubernetes
	Gateways      []GatewayConfig `yaml:"gateways"`
	// TLS is the mutual-TLS material the core presents when dialing gateways.
	TLS GatewayTLSConfig `yaml:"tls"`
}

// GatewayTLSConfig holds the core's client identity for the gateway channel.
type GatewayTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// Insecure disables TLS on the gateway channel. The channel carries CSRs,
	// private keys, and CA credentials, so this is development-only.
	Insecure bool `yaml:"insecure"`
}

// GatewayConfig represents a single gateway registration.
type GatewayConfig struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
	Type string `yaml:"type"`
	// ServerName overrides the name expected in this gateway's certificate,
	// for when it is dialed by IP or through a service alias.
	ServerName string `yaml:"server_name"`
}

// PKIConfig holds PKI monitoring settings.
type PKIConfig struct {
	CAHealthCheckInterval int `yaml:"ca_health_check_interval"` // minutes
	CRLOCSPCheckInterval  int `yaml:"crl_ocsp_check_interval"`  // minutes
}

// RenewalConfig holds certificate renewal settings.
type RenewalConfig struct {
	ScanInterval    int   `yaml:"scan_interval"` // minutes
	DefaultLeadDays int   `yaml:"default_lead_days"`
	RetryBackoff    []int `yaml:"retry_backoff"` // minutes
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // text | json
}

// GatewayPluginConfig is the configuration for a gateway plugin process.
type GatewayPluginConfig struct {
	Port     int    `yaml:"port"`
	CoreAddr string `yaml:"core_addr"` // Address of the CertPilot Core gRPC endpoint
}

// LoadCoreConfig loads the core configuration from a YAML file.
func LoadCoreConfig(path string) (*CoreConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	cfg := &CoreConfig{
		// Defaults
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			Mode:           "development",
			AllowedOrigins: []string{"http://localhost:3000"},
		},
		Auth: AuthConfig{
			RoleClaim: "certpilot_role",
		},
		PKI: PKIConfig{
			CAHealthCheckInterval: 360,
			CRLOCSPCheckInterval:  60,
		},
		Renewal: RenewalConfig{
			ScanInterval:    60,
			DefaultLeadDays: 30,
			RetryBackoff:    []int{60, 240, 720, 1440},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}

	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.Auth.RoleClaim == "" {
		cfg.Auth.RoleClaim = "certpilot_role"
	}
	if len(cfg.Auth.Scopes) == 0 {
		// openid is what makes it an OIDC request at all; the other two are
		// what let a users list show a name instead of an opaque subject.
		cfg.Auth.Scopes = []string{"openid", "profile", "email"}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate rejects configurations that are unsafe to run.
//
// These checks exist because the dangerous settings here are all ones that look
// harmless in a development config and then travel to production unnoticed.
func (c *CoreConfig) Validate() error {
	// Refused everywhere, not only in production. There is no mode in which
	// CertPilot serves an unauthenticated caller any more.
	if c.Auth.AllowAnonymous {
		return fmt.Errorf("config: auth.allow_anonymous no longer exists and must be removed. " +
			"CertPilot now requires a sign-in everywhere, including locally: use a local " +
			"account, or configure auth.jwks_url for an identity provider")
	}

	// Checked here rather than at start-up, so a typo is a configuration error
	// on the way in rather than a fall back to the environment — which would
	// look like it worked until somebody noticed the key was still in an env
	// var they thought they had removed.
	switch c.Secrets.KEKProvider {
	case "", "env":
	case "file":
		if c.Secrets.KEKFile == "" {
			return fmt.Errorf("config: secrets.kek_provider is \"file\" but secrets.kek_file is not set")
		}
	case "vault":
		if c.Secrets.Vault.Address == "" || c.Secrets.Vault.Path == "" {
			return fmt.Errorf("config: secrets.kek_provider is \"vault\" but secrets.vault.address " +
				"or secrets.vault.path is not set")
		}
	default:
		return fmt.Errorf("config: secrets.kek_provider %q is not one of env, file, vault",
			c.Secrets.KEKProvider)
	}

	if c.ACME.Enabled && c.Server.IsProduction() {
		if !strings.HasPrefix(c.ACME.ExternalURL, "https://") {
			return fmt.Errorf("config: acme.enabled needs acme.external_url set to the https address clients use; " +
				"an ACME client signs every request for the URL it was given, and a core that guesses its own " +
				"address behind a proxy will refuse them all")
		}
		if c.ACME.Challenges.Port() != 80 {
			return fmt.Errorf("config: acme.challenges.http_port is %d; in production HTTP-01 is checked on port 80, "+
				"as RFC 8555 says, and another port would accept proof no public CA would", c.ACME.Challenges.HTTPPort)
		}
	}

	if c.Server.IsProduction() {
		if c.Plugins.TLS.Insecure {
			return fmt.Errorf("config: plugins.tls.insecure cannot be enabled in production mode; " +
				"the gateway channel carries private keys and CA credentials")
		}
		for _, origin := range c.Server.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("config: server.allowed_origins cannot contain \"*\" in production mode")
			}
		}
	}

	return nil
}
