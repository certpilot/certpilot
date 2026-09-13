package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/certpilot/certpilot/agent"
)

// runProfiles answers "does CertPilot cover what I run".
//
// It is a local, offline command on purpose. The question it answers is asked
// by somebody deciding whether this tool applies to their estate, which is
// before they have a core to ask, an enrolment token, or any reason to trust a
// network service with the question.
func runProfiles(args []string) error {
	fs := flag.NewFlagSet("profiles", flag.ExitOnError)
	detect := fs.Bool("detect", false, "report which of these platforms appear to be installed here")
	asJSON := fs.Bool("json", false, "print the catalogue as JSON")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `certpilot-agent profiles [NAME] [--detect] [--json]

  profiles              every platform, and what it installs
  profiles nginx        one platform in full: paths, commands, and what to know
  profiles --detect     which of them appear to be installed on this host
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *detect {
		return printDetected(*asJSON)
	}
	if name := fs.Arg(0); name != "" {
		p, ok := agent.LookupProfile(name)
		if !ok {
			return fmt.Errorf("no profile called %q — try one of: %s",
				name, strings.Join(agent.ProfileNames(), ", "))
		}
		if *asJSON {
			return printJSON(p)
		}
		printProfile(p)
		return nil
	}

	all := agent.Profiles()
	if *asJSON {
		return printJSON(all)
	}
	fmt.Printf("%d platforms. Each one has been installed to: a container running the\n", len(all))
	fmt.Print("real service, a certificate installed by this agent, and a TLS handshake\n")
	fmt.Print("proving the service served it after its own reload.\n\n")
	for _, p := range all {
		fmt.Printf("  %-12s %s\n", p.Name, p.Platform)
		fmt.Printf("  %-12s %s\n", "", p.Summary)
		fmt.Println()
	}
	fmt.Print("`certpilot-agent profiles NAME` for the paths, the commands and the caveats.\n")
	fmt.Print("A profile fills in a destination; anything you write yourself wins.\n")
	return nil
}

func printProfile(p agent.Profile) {
	fmt.Printf("%s (%s)\n\n", p.Platform, p.Name)
	fmt.Printf("  %s\n\n", p.Summary)

	fmt.Print("Declare it:\n\n")
	fmt.Printf("  {\n    \"name\": \"%s\",\n    \"certificate\": \"www.example.com\",\n    \"profile\": \"%s\"%s\n  }\n\n",
		p.Name, p.Name, extraFields(p))

	fmt.Print("Which fills in:\n\n")
	row := func(label, value string) {
		if value != "" {
			fmt.Printf("  %-16s %s\n", label, value)
		}
	}
	row("format", orDefault(p.Format, "PEM"))
	row("cert_path", p.CertPath)
	row("key_path", p.KeyPath)
	row("chain_path", p.ChainPath)
	row("fullchain_path", p.FullChainPath)
	row("owner", p.Owner)
	row("group", p.Group)
	row("cert_mode", p.CertMode)
	row("key_mode", p.KeyMode)
	if len(p.Check) > 0 {
		row("check", strings.Join(p.Check, " "))
	} else {
		row("check", "— none; this platform has no configuration validator")
	}
	row("reload", strings.Join(p.Reload, " "))
	fmt.Println()

	if len(p.Detect) > 0 {
		fmt.Print("Looked for on this host:\n\n")
		for _, d := range p.Detect {
			fmt.Printf("  %s\n", d)
		}
		fmt.Println()
	}

	if len(p.Notes) > 0 {
		fmt.Print("Worth knowing:\n\n")
		for _, n := range p.Notes {
			fmt.Println(wrap("  - ", "    ", n))
		}
	}
	if p.Verified != "" {
		fmt.Printf("\nVerified against %s.\n", p.Verified)
	}
}

// extraFields names what a profile cannot supply and the operator must.
func extraFields(p agent.Profile) string {
	if p.Format == agent.FormatPKCS12 {
		return ",\n    \"keystore_password_file\": \"/etc/certpilot/keystore-password\""
	}
	return ""
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func printDetected(asJSON bool) error {
	found := agent.DetectProfiles()
	if asJSON {
		return printJSON(found)
	}
	if len(found) == 0 {
		fmt.Print("None of the catalogue's platforms were found on this host.\n\n")
		fmt.Print("That is a statement about files, not about support. Detection looks for a\n")
		fmt.Print("configuration file in the usual place; a service installed somewhere else\n")
		fmt.Print("is still perfectly installable — write the paths yourself.\n")
		return nil
	}
	fmt.Printf("%d of the catalogue's platforms look installed here:\n\n", len(found))
	for _, p := range found {
		fmt.Printf("  %-12s %s\n", p.Name, p.Platform)
	}
	fmt.Print("\nWhat this means: a file exists where this platform usually keeps one. It\n")
	fmt.Print("does **not** mean the profile's paths are the ones your service reads —\n")
	fmt.Print("your configuration decides that, and nothing here has looked at it. Run\n")
	fmt.Print("`certpilot-agent profiles NAME`, compare it against the configuration you\n")
	fmt.Print("actually have, and change whatever does not match.\n")
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// wrap reflows a note to something readable in a terminal.
func wrap(first, rest string, text string) string {
	const width = 74
	var out strings.Builder
	out.WriteString(first)
	column := len(first)
	for i, word := range strings.Fields(text) {
		if i > 0 && column+1+len(word) > width {
			out.WriteString("\n" + rest)
			column = len(rest)
		} else if i > 0 {
			out.WriteString(" ")
			column++
		}
		out.WriteString(word)
		column += len(word)
	}
	return out.String()
}
