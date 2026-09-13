// Command certpilot-agent runs on the machines where certificates actually
// live.
//
// The agent generates its keys on the host and never sends a private one
// anywhere — starting with its own identity key, which it creates during
// enrolment. That is the whole architectural claim, and it is why this is a
// separate binary and a separate Go module: it must be small, it must be
// installable on a machine that can reach nothing but the core, and it must not
// link a line of the core's database code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	"github.com/certpilot/certpilot/agent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "enrol", "enroll":
		err = runEnrol(ctx, os.Args[2:])
	case "run":
		err = runAgent(ctx, os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "request":
		err = runRequest(ctx, os.Args[2:])
	case "install":
		err = runInstall(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	case "-v", "--version", "version":
		// Answered before anything is initialised: asking a binary what it is
		// must work on a host where nothing else about it does — no state
		// directory, no enrolment, no network.
		fmt.Println(agent.Version)
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `certpilot-agent — the CertPilot host agent

  certpilot-agent enrol  --server=URL --token=TOKEN [--name=NAME] [--interval=5m]
  certpilot-agent run    [--state-dir=DIR] [--installs=FILE]
  certpilot-agent scan   [--path=DIR ...]      what this host would report
  certpilot-agent request --name=HOST [--name=...] [--key-type=ECDSA]
  certpilot-agent install [--installs=FILE] [--force] [--offline]
  certpilot-agent status [--state-dir=DIR]
  certpilot-agent version

Enrolment generates this host's identity key locally. The private half is never
sent to the core and there is no flag that would send it.

Destinations — which files a certificate is written to and what to run
afterwards — are read from a file on this host, never sent by the core.

State directory defaults to `+"`"+`$CERTPILOT_AGENT_STATE`+"`"+`, then /var/lib/certpilot-agent
when running as root, then ~/.certpilot-agent.
`)
}

func runEnrol(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enrol", flag.ExitOnError)
	server := fs.String("server", "", "CertPilot core base URL, e.g. https://certpilot.internal:8080")
	token := fs.String("token", "", "an enrolment token")
	name := fs.String("name", "", "what to call this host in CertPilot (defaults to its hostname)")
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where to keep this agent's identity")
	interval := fs.Duration("interval", 5*time.Minute, "how often this agent will report")
	var paths stringList
	fs.Var(&paths, "path", "a directory to scan for certificates (repeatable; defaults are used if unset)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := agent.Enrol(ctx, agent.EnrolOptions{
		Server:    *server,
		Token:     *token,
		Name:      *name,
		StateDir:  *stateDir,
		Interval:  *interval,
		ScanPaths: paths,
	})
	if err != nil {
		return err
	}

	// The key id is printed so an operator can compare it with the row in
	// CertPilot and answer "is the agent enrolled under this name the machine I
	// ran this on" without trusting the name, which anybody can set.
	fmt.Printf("Enrolled as %q\n", result.Name)
	fmt.Printf("  agent id : %s\n", result.AgentID)
	fmt.Printf("  key id   : %s\n", result.KeyID)
	fmt.Printf("  identity : %s (private key never leaves this host)\n", *stateDir)
	fmt.Printf("\nStart reporting with: certpilot-agent run --state-dir=%s\n", *stateDir)
	return nil
}

func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	specPath := fs.String("installs", "", "where the destinations are declared (defaults to /etc/certpilot/installs.json)")
	once := fs.Bool("once", false, "do one cycle — heartbeat, renew, install, inventory — then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}

	runner := agent.NewRunner(agent.NewClient(state.Server, state.AgentID, key), state, *stateDir).
		WithSpecPath(*specPath)
	if *once {
		// Everything one cycle of the daemon would do: report, renew what is
		// due, and inventory. "Once" has to mean all of it, or an estate
		// running this from a systemd timer rather than as a daemon — which
		// plenty will — would have an agent that says it is alive and never
		// rotates a key.
		if _, err := runner.Heartbeat(ctx); err != nil {
			return err
		}
		renewed := runner.RenewDue(ctx)
		installed := runner.InstallCycle(ctx, true)
		report, err := runner.ReportInventory(ctx)
		if err != nil {
			return err
		}
		if renewed > 0 {
			fmt.Printf("renewed %d certificate(s)\n", renewed)
		}
		for _, inst := range installed.Installations {
			fmt.Printf("%-12s %-12s %s\n", inst.Name, inst.Status, installDetail(inst))
		}
		fmt.Printf("reported: %d certificate file(s) from %d file(s) scanned\n",
			len(report.Certificates), report.FilesSeen)
		return nil
	}
	return runner.Run(ctx)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// runScan prints what this host would report, and sends nothing.
//
// A dry run first is the right posture for something that walks a production
// filesystem: whoever is about to install this on four hundred machines should
// be able to see the output of one before any of it leaves the host.
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var paths stringList
	fs.Var(&paths, "path", "a directory to scan (repeatable; defaults are used if unset)")
	asJSON := fs.Bool("json", false, "print the report exactly as it would be sent")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := agent.Scan(paths)
	if *asJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
		return nil
	}

	fmt.Printf("Scanned %d files under %s\n", report.FilesSeen, strings.Join(report.Paths, ", "))
	fmt.Printf("Found %d certificate file(s)\n\n", len(report.Certificates))
	for _, found := range report.Certificates {
		fmt.Printf("  %s\n", found.Path)
		fmt.Printf("    %s  mode %s  owner %s  fingerprint %s…\n",
			found.Kind, found.Mode, found.Owner, found.Fingerprint[:16])
		switch {
		case found.PrivateKeyInSameFile:
			fmt.Printf("    private key: in this file, mode %s%s\n", found.PrivateKeyMode, matchNote(found))
		case found.PrivateKeyPath != "":
			fmt.Printf("    private key: %s, mode %s%s\n", found.PrivateKeyPath, found.PrivateKeyMode, matchNote(found))
		case found.Kind == agentapi.KindLeaf:
			fmt.Printf("    private key: none found beside it — this host cannot serve this certificate\n")
		}
		if len(found.ReferencedBy) > 0 {
			fmt.Printf("    referenced by: %s\n", strings.Join(found.ReferencedBy, ", "))
		}
		fmt.Println()
	}
	for _, e := range report.Errors {
		fmt.Printf("  could not read: %s\n", e)
	}
	if report.Truncated {
		fmt.Println("  (the scan hit its own limits; this list is incomplete)")
	}
	// Said out loud, because it is the thing somebody about to roll this out
	// wants to be sure of.
	fmt.Println("Nothing was sent. Private keys are never read into a report — only")
	fmt.Println("whether one is there, whether it matches, and what its permissions are.")
	return nil
}

func matchNote(found agent.Discovered) string {
	if found.PrivateKeyMatches {
		return ""
	}
	return "  ** does not match this certificate **"
}

// runRequest asks the core for a certificate, with a key generated here.
func runRequest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	var names stringList
	fs.Var(&names, "name", "a hostname to request (repeatable)")
	keyType := fs.String("key-type", "ECDSA", "ECDSA, RSA, or Ed25519")
	keySize := fs.Int("key-size", 0, "key size; defaults to 256 for ECDSA, 2048 for RSA")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("--name is required: the hostname this certificate is for")
	}

	key, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	runner := agent.NewRunner(agent.NewClient(state.Server, state.AgentID, key), state, *stateDir)

	held, err := runner.Request(ctx, agent.RequestOptions{
		Names: names, KeyType: *keyType, KeySize: *keySize,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Issued for %s\n", strings.Join(held.Names, ", "))
	fmt.Printf("  expires    : %s\n", held.NotAfter.Format(time.RFC3339))
	fmt.Printf("  renew after: %s (the core decides this, not this host)\n",
		held.RenewAfter.Format(time.RFC3339))
	fmt.Printf("  files      : %s\n", held.Directory)
	fmt.Println()
	fmt.Println("The private key was generated on this host and was never sent anywhere.")
	fmt.Println("CertPilot cannot produce it, and does not claim to.")
	return nil
}

// runInstall applies this host's destinations without waiting for a cycle.
//
// The command somebody runs after editing the spec file, and the one they run
// during an incident. --offline does the local work and tells the core nothing,
// which is what a host with a broken credential or an unreachable core still
// needs to be able to do: installing a certificate this machine already holds
// requires no permission from anywhere.
func runInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where this agent's identity is kept")
	specPath := fs.String("installs", "", "where the destinations are declared (defaults to /etc/certpilot/installs.json)")
	force := fs.Bool("force", false, "rewrite and reload even when the files already match")
	offline := fs.Bool("offline", false, "do the local work and report nothing to the core")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *offline {
		// No identity is loaded at all on this path. A host whose credential
		// has been revoked can still put the certificate it holds where its
		// server reads it.
		path := *specPath
		if path == "" {
			path = agent.DefaultSpecPath(*stateDir)
		}
		spec, err := agent.LoadInstallSpec(path)
		if err != nil {
			return err
		}
		if !spec.Found {
			return fmt.Errorf("no destinations are declared on this host; expected %s", path)
		}
		held := agent.HeldIn(*stateDir)
		report := agent.NewInstaller(spec, path, held).Apply(ctx, forceAll(spec, *force))
		return printInstallations(report)
	}

	key, state, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	runner := agent.NewRunner(agent.NewClient(state.Server, state.AgentID, key), state, *stateDir).
		WithSpecPath(*specPath)
	if *force {
		return printInstallations(runner.ForceInstall(ctx))
	}
	return printInstallations(runner.InstallCycle(ctx, true))
}

// forceAll builds the force set for an offline run.
func forceAll(spec agent.InstallSpec, force bool) map[string]bool {
	if !force {
		return nil
	}
	out := map[string]bool{}
	for _, d := range spec.Destinations {
		out[d.Name] = true
	}
	return out
}

func printInstallations(report agentapi.InstallationReport) error {
	if len(report.Installations) == 0 && len(report.Errors) == 0 {
		fmt.Println("no destinations are declared on this host")
		return nil
	}
	for _, problem := range report.Errors {
		fmt.Printf("error: %s\n", problem)
	}
	failed := 0
	for _, inst := range report.Installations {
		fmt.Printf("%-14s %-12s %s\n", inst.Name, inst.Status, installDetail(inst))
		if inst.Status == agentapi.InstallFailed {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d destination(s) could not be installed", failed)
	}
	return nil
}

// installDetail picks the sentence worth printing for one destination.
func installDetail(inst agentapi.Installation) string {
	if inst.Error != "" {
		if inst.Detail != "" {
			return inst.Error + " — " + inst.Detail
		}
		return inst.Error
	}
	return inst.Detail
}
