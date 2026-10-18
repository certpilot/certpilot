package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/acmeserver"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"golang.org/x/crypto/acme"
)

// world is the outside the core validates against: every name resolves to a
// local web server, which answers HTTP-01 from a table, and TXT records come
// from another table.
type world struct {
	mu   sync.Mutex
	http map[string]string // path -> body
	code map[string]int    // path -> status, when not 200
	move map[string]string // path -> where it redirects
	hits int
	txt  map[string][]string
	srv  *httptest.Server
	port int
}

func newWorld(t *testing.T) *world {
	w := &world{http: map[string]string{}, code: map[string]int{}, move: map[string]string{}, txt: map[string][]string{}}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.hits++
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		body, ok := w.http[host+r.URL.Path]
		code := w.code[host+r.URL.Path]
		to, moved := w.move[host+r.URL.Path]
		w.mu.Unlock()
		if moved {
			http.Redirect(rw, r, to, http.StatusFound)
			return
		}
		if !ok {
			http.NotFound(rw, r)
			return
		}
		if code != 0 {
			rw.WriteHeader(code)
		}
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(w.srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(w.srv.URL, "http://"))
	w.port, _ = strconv.Atoi(port)
	return w
}

func (w *world) LookupHost(_ context.Context, host string) ([]string, error) {
	if strings.HasSuffix(host, ".invalid") {
		return nil, errors.New("no such host")
	}
	return []string{"127.0.0.1"}, nil
}

func (w *world) LookupTXT(_ context.Context, name string) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if v, ok := w.txt[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such record")
}

func (w *world) serve(host, token, body string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.http[host+"/.well-known/acme-challenge/"+token] = body
}

func (w *world) serveAt(host, path, body string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.http[host+path] = body
}

func (w *world) redirect(host, token, to string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.move[host+"/.well-known/acme-challenge/"+token] = to
}

func (w *world) record(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.txt[name] = append(w.txt[name], value)
}

// challengedFixture is a server whose credentials, made with challenged,
// require proof of control.
func challengedFixture(t *testing.T) (*fixture, *world) {
	w := newWorld(t)
	f := newFixtureWith(t, func(c *acmeserver.Config) {
		c.Validation = acmeserver.Validation{HTTPPort: w.port, Resolver: w, Timeout: 5 * time.Second}
	})
	return f, w
}

func (f *fixture) challengedClient() *acme.Client {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sealed, _ := f.kr.Encrypt(key, secrets.ContextACMEEABKey)
	kid := "proof-" + strings.ReplaceAll(f.t.Name(), "/", "-")
	if err := f.st.CreateACMEEABCredential(context.Background(), &store.ACMEEABCredential{
		KID: kid, Name: kid, TemplateID: f.template.ID, HMACKeySealed: sealed, RequireChallenge: true,
	}); err != nil {
		f.t.Fatal(err)
	}
	c := f.client()
	if _, err := register(c, kid, key); err != nil {
		f.t.Fatal(err)
	}
	return c
}

func challenge(t *testing.T, authz *acme.Authorization, kind string) *acme.Challenge {
	t.Helper()
	for _, ch := range authz.Challenges {
		if ch.Type == kind {
			return ch
		}
	}
	t.Fatalf("no %s challenge offered: %+v", kind, authz.Challenges)
	return nil
}

func finalize(t *testing.T, c *acme.Client, order *acme.Order, names ...string) error {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	_, _, err := c.CreateOrderCert(context.Background(), order.FinalizeURL, csr, true)
	return err
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestAnOrderWaitsForProofWhenTheCredentialRequiresIt(t *testing.T) {
	f, _ := challengedFixture(t)
	c := f.challengedClient()
	order, err := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com", "*.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != acme.StatusPending {
		t.Fatalf("order is %s, want pending until each name is proved", order.Status)
	}
	plain, err := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	if err != nil || plain.Status != acme.StatusPending {
		t.Fatalf("authorization: %+v, %v", plain, err)
	}
	challenge(t, plain, "http-01")
	challenge(t, plain, "dns-01")

	// RFC 8555 §8.3: a wildcard cannot be proved over HTTP.
	wild, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[1])
	if !wild.Wildcard || wild.Identifier.Value != "example.com" {
		t.Errorf("wildcard authorization: %+v", wild)
	}
	for _, ch := range wild.Challenges {
		if ch.Type == "http-01" {
			t.Error("a wildcard was offered http-01")
		}
	}

	if err := finalize(t, c, order, "web.example.com", "*.example.com"); problemType(err) != "urn:ietf:params:acme:error:orderNotReady" {
		t.Errorf("finalize before proof: %v, want orderNotReady", err)
	}
	if f.gw.issued.Load() != 0 {
		t.Error("the CA was asked before the names were proved")
	}
}

func TestHTTP01ProvesAName(t *testing.T) {
	f, w := challengedFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "http-01")
	body, _ := c.HTTP01ChallengeResponse(ch.Token)
	w.serve("web.example.com", ch.Token, body+"\n")

	if _, err := c.Accept(ctx(t), ch); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := c.WaitAuthorization(ctx(t), authz.URI); err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if got, err := c.WaitOrder(ctx(t), order.URI); err != nil || got.Status != acme.StatusReady {
		t.Fatalf("order: %+v, %v; want ready", got, err)
	}
	if err := finalize(t, c, order, "web.example.com"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
}

func TestDNS01ProvesAWildcard(t *testing.T) {
	f, w := challengedFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("*.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "dns-01")
	value, _ := c.DNS01ChallengeRecord(ch.Token)
	w.record("_acme-challenge.example.com", "something else")
	w.record("_acme-challenge.example.com", value)

	if _, err := c.Accept(ctx(t), ch); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := c.WaitAuthorization(ctx(t), authz.URI); err != nil {
		t.Fatalf("authorization: %v", err)
	}
	// Ready, so proved. Whether a wildcard is then issued is the template's
	// to say, at finalize; this one's does not allow them.
	if got, err := c.WaitOrder(ctx(t), order.URI); err != nil || got.Status != acme.StatusReady {
		t.Fatalf("order: %+v, %v; want ready", got, err)
	}
}

// A failed proof ends the authorization and the order: RFC 8555 §7.1.6. The
// client starts again with a new order rather than retrying a challenge.
func TestAProofThatDoesNotHoldFailsTheOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		setup func(w *world, c *acme.Client, ch *acme.Challenge)
		kind  string
	}{
		{"the wrong key authorization", []string{"web.example.com"}, func(w *world, c *acme.Client, ch *acme.Challenge) {
			w.serve("web.example.com", ch.Token, ch.Token+".not-the-account-key")
		}, "http-01"},
		{"nothing served", []string{"web.example.com"}, func(*world, *acme.Client, *acme.Challenge) {}, "http-01"},
		// Some servers echo the path they could not find. An error page that
		// happens to hold the answer is still an error page.
		{"the right answer, as an error", []string{"web.example.com"}, func(w *world, c *acme.Client, ch *acme.Challenge) {
			body, _ := c.HTTP01ChallengeResponse(ch.Token)
			w.serve("web.example.com", ch.Token, body)
			w.mu.Lock()
			w.code["web.example.com/.well-known/acme-challenge/"+ch.Token] = http.StatusNotFound
			w.mu.Unlock()
		}, "http-01"},
		{"a name that does not resolve", []string{"gone.invalid"}, func(*world, *acme.Client, *acme.Challenge) {}, "http-01"},
		{"no TXT record", []string{"web.example.com"}, func(*world, *acme.Client, *acme.Challenge) {}, "dns-01"},
		{"a TXT record for another account", []string{"web.example.com"}, func(w *world, _ *acme.Client, ch *acme.Challenge) {
			w.record("_acme-challenge.web.example.com", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		}, "dns-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, w := challengedFixture(t)
			c := f.challengedClient()
			order, err := c.AuthorizeOrder(ctx(t), acme.DomainIDs(tc.names...))
			if err != nil {
				t.Fatal(err)
			}
			authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
			ch := challenge(t, authz, tc.kind)
			tc.setup(w, c, ch)
			_, _ = c.Accept(ctx(t), ch)

			got, err := c.GetAuthorization(ctx(t), authz.URI)
			if err != nil || got.Status != acme.StatusInvalid {
				t.Fatalf("authorization: %+v, %v; want invalid", got, err)
			}
			for _, gch := range got.Challenges {
				if gch.Type == tc.kind && (gch.Status != acme.StatusInvalid || gch.Error == nil) {
					t.Errorf("the challenge is %s with error %v; want invalid and saying why", gch.Status, gch.Error)
				}
			}
			if o, _ := c.GetOrder(ctx(t), order.URI); o == nil || o.Status != acme.StatusInvalid {
				t.Errorf("order %+v; want invalid", o)
			}
		})
	}
}

func TestOnlyTheOrderingAccountCanAnswerItsChallenges(t *testing.T) {
	f, w := challengedFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "http-01")
	body, _ := c.HTTP01ChallengeResponse(ch.Token)
	w.serve("web.example.com", ch.Token, body)

	other := f.registered()
	if _, err := other.Accept(ctx(t), ch); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("another account accepted it: %v", err)
	}
	if got, _ := c.GetAuthorization(ctx(t), authz.URI); got.Status != acme.StatusPending {
		t.Errorf("authorization is %s after another account answered", got.Status)
	}
}

// Without the setting, nothing changes: the credential is the authorisation.
func TestACredentialThatDoesNotRequireProofStaysPreAuthorised(t *testing.T) {
	f, _ := challengedFixture(t)
	order, err := f.registered().AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	if err != nil || order.Status != acme.StatusReady {
		t.Fatalf("order %+v, %v; want ready", order, err)
	}
}

func TestAnOrderIsReadyOnlyWhenEveryNameIsProved(t *testing.T) {
	f, w := challengedFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com", "api.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "http-01")
	body, _ := c.HTTP01ChallengeResponse(ch.Token)
	w.serve("web.example.com", ch.Token, body)
	if _, err := c.Accept(ctx(t), ch); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.GetOrder(ctx(t), order.URI); got.Status != acme.StatusPending {
		t.Errorf("order is %s with one of two names proved; want pending", got.Status)
	}
}

// An authorization is decided once. Answering again after a failure, with the
// right answer this time, does not revive it: the client orders again.
func TestAFailedAuthorizationStaysFailed(t *testing.T) {
	f, w := challengedFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "http-01")
	_, _ = c.Accept(ctx(t), ch)

	body, _ := c.HTTP01ChallengeResponse(ch.Token)
	w.serve("web.example.com", ch.Token, body)
	_, _ = c.Accept(ctx(t), ch)
	if got, _ := c.GetAuthorization(ctx(t), authz.URI); got.Status != acme.StatusInvalid {
		t.Errorf("authorization is %s after a second answer; want it still invalid", got.Status)
	}
}

func TestAnExpiredAuthorizationCannotBeProved(t *testing.T) {
	w := newWorld(t)
	var clock struct {
		sync.Mutex
		now time.Time
	}
	clock.now = time.Now()
	f := newFixtureWith(t, func(c *acmeserver.Config) {
		c.Validation = acmeserver.Validation{HTTPPort: w.port, Resolver: w, Timeout: 5 * time.Second}
		c.Now = func() time.Time { clock.Lock(); defer clock.Unlock(); return clock.now }
	})
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "http-01")
	body, _ := c.HTTP01ChallengeResponse(ch.Token)
	w.serve("web.example.com", ch.Token, body)

	clock.Lock()
	clock.now = clock.now.Add(48 * time.Hour)
	clock.Unlock()
	_, _ = c.Accept(ctx(t), ch)
	if got, _ := c.GetAuthorization(ctx(t), authz.URI); got.Status != acme.StatusInvalid {
		t.Errorf("an expired authorization is %s after a correct answer; want invalid", got.Status)
	}
}

// tlsWorld answers TLS-ALPN-01 on a local port with whatever certificate the
// test sets for a name, and speaks acme-tls/1 unless told not to.
type tlsWorld struct {
	*world
	mu      sync.Mutex
	certs   map[string]tls.Certificate
	noALPN  bool
	tlsPort int
}

func newTLSWorld(t *testing.T) *tlsWorld {
	tw := &tlsWorld{world: newWorld(t), certs: map[string]tls.Certificate{}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			tw.mu.Lock()
			defer tw.mu.Unlock()
			cert, ok := tw.certs[hello.ServerName]
			if !ok {
				return nil, errors.New("no certificate for " + hello.ServerName)
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
			if !tw.noALPN {
				cfg.NextProtos = []string{"acme-tls/1"}
			}
			return cfg, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = conn.(*tls.Conn).Handshake(); conn.Close() }()
		}
	}()
	tw.tlsPort = l.Addr().(*net.TCPAddr).Port
	return tw
}

func tlsFixture(t *testing.T) (*fixture, *tlsWorld) {
	tw := newTLSWorld(t)
	f := newFixtureWith(t, func(c *acmeserver.Config) {
		c.Validation = acmeserver.Validation{HTTPPort: tw.port, TLSPort: tw.tlsPort, Resolver: tw, Timeout: 5 * time.Second}
	})
	return f, tw
}

func TestTLSALPN01ProvesAName(t *testing.T) {
	f, tw := tlsFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	ch := challenge(t, authz, "tls-alpn-01")
	cert, err := c.TLSALPN01ChallengeCert(ch.Token, "web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tw.mu.Lock()
	tw.certs["web.example.com"] = cert
	tw.mu.Unlock()

	if _, err := c.Accept(ctx(t), ch); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, err := c.WaitOrder(ctx(t), order.URI); err != nil || got.Status != acme.StatusReady {
		t.Fatalf("order: %+v, %v; want ready", got, err)
	}
}

func TestATLSALPN01AnswerThatDoesNotHoldFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(tw *tlsWorld, c *acme.Client, token string)
	}{
		{"the certificate is for another account's key authorization", func(tw *tlsWorld, _ *acme.Client, token string) {
			other := &acme.Client{Key: newKey(t)}
			cert, _ := other.TLSALPN01ChallengeCert(token, "web.example.com")
			tw.certs["web.example.com"] = cert
		}},
		{"the certificate is for another name", func(tw *tlsWorld, c *acme.Client, token string) {
			cert, _ := c.TLSALPN01ChallengeCert(token, "other.example.com")
			tw.certs["web.example.com"] = cert
		}},
		{"the server does not speak acme-tls/1", func(tw *tlsWorld, c *acme.Client, token string) {
			cert, _ := c.TLSALPN01ChallengeCert(token, "web.example.com")
			tw.certs["web.example.com"] = cert
			tw.noALPN = true
		}},
		{"an ordinary certificate", func(tw *tlsWorld, _ *acme.Client, _ string) {
			key := newKey(t)
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"web.example.com"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			tw.certs["web.example.com"] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, tw := tlsFixture(t)
			c := f.challengedClient()
			order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
			authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
			ch := challenge(t, authz, "tls-alpn-01")
			tw.mu.Lock()
			tc.setup(tw, c, ch.Token)
			tw.mu.Unlock()
			_, _ = c.Accept(ctx(t), ch)
			if got, _ := c.GetAuthorization(ctx(t), authz.URI); got.Status != acme.StatusInvalid {
				t.Errorf("authorization is %s; want invalid", got.Status)
			}
		})
	}
}

func TestAWildcardIsNotOfferedTLSALPN01(t *testing.T) {
	f, _ := tlsFixture(t)
	c := f.challengedClient()
	order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("*.example.com"))
	authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
	for _, ch := range authz.Challenges {
		if ch.Type != "dns-01" {
			t.Errorf("a wildcard was offered %s", ch.Type)
		}
	}
}

// RFC 8555 §8.3: HTTP-01 follows redirects. Only to http or https, on the two
// challenge ports, and to a name rather than an address: nowhere a challenge
// could not reach anyway.
func TestHTTP01FollowsRedirectsWithinTheChallengePorts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		to    func(f *fixture, tw *tlsWorld, token string) string
		valid bool
		// says is what the refusal names, so each case fails for its own
		// reason rather than for whatever happens after the redirect.
		says string
	}{
		{"to another path", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://web.example.com:%d/moved/%s", tw.port, token)
		}, true, ""},
		{"to an address", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://127.0.0.1:%d/moved/%s", tw.port, token)
		}, false, "only to the name being proved"},
		// An address spelled as a number, which net.ParseIP does not read as
		// one and a resolver may: why the rule is the name, not "not an IP".
		{"to an address spelled as a number", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://2130706433:%d/moved/%s", tw.port, token)
		}, false, "only to the name being proved"},
		{"to another name", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://cdn.example.com:%d/moved/%s", tw.port, token)
		}, false, "only to the name being proved"},
		{"to another port", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://web.example.com:%d/moved/%s", tw.port+1, token)
		}, false, "may only go to port"},
		{"to another scheme", func(f *fixture, tw *tlsWorld, token string) string {
			return "ftp://web.example.com/moved/" + token
		}, false, "only http and https"},
		{"round in circles", func(f *fixture, tw *tlsWorld, token string) string {
			return fmt.Sprintf("http://web.example.com:%d/.well-known/acme-challenge/%s", tw.port, token)
		}, false, "more than 10 redirects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, tw := tlsFixture(t)
			c := f.challengedClient()
			order, _ := c.AuthorizeOrder(ctx(t), acme.DomainIDs("web.example.com"))
			authz, _ := c.GetAuthorization(ctx(t), order.AuthzURLs[0])
			ch := challenge(t, authz, "http-01")
			body, _ := c.HTTP01ChallengeResponse(ch.Token)
			tw.redirect("web.example.com", ch.Token, tc.to(f, tw, ch.Token))
			for _, host := range []string{"web.example.com", "127.0.0.1", "2130706433", "cdn.example.com"} {
				tw.serveAt(host, "/moved/"+ch.Token, body)
			}

			_, _ = c.Accept(ctx(t), ch)
			got, _ := c.GetAuthorization(ctx(t), authz.URI)
			if want := map[bool]string{true: acme.StatusValid, false: acme.StatusInvalid}[tc.valid]; got.Status != want {
				t.Fatalf("authorization is %s; want %s", got.Status, want)
			}
			tw.world.mu.Lock()
			hits := tw.world.hits
			tw.world.mu.Unlock()
			if hits > 11 {
				t.Errorf("%d fetches; a redirect chain is followed at most ten times", hits)
			}
			if tc.says != "" {
				detail := ""
				for _, gch := range got.Challenges {
					if gch.Type == "http-01" && gch.Error != nil {
						detail = gch.Error.Error()
					}
				}
				if !strings.Contains(detail, tc.says) {
					t.Errorf("refused saying %q; want it to say %q", detail, tc.says)
				}
			}
		})
	}
}
