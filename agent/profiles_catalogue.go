package agent

// The catalogue.
//
// Ordering is by how many estates a profile unblocks, not alphabetical: the
// web servers first, then the services that terminate TLS without anybody
// thinking of them as web servers — which is where the certificates nobody is
// tracking usually are.
//
// # Why the reload is usually not systemctl
//
// A packaged host runs these under systemd, so `systemctl reload nginx` is the
// obvious default and it is the wrong one. Unit names are a distribution's
// choice, not a platform's: Apache is `apache2` on Debian and `httpd` on Red
// Hat, and a profile that guessed would be wrong for half the hosts that used
// it. The platform's own reload command is the same everywhere, and on a
// systemd host it is the same operation the unit performs — Debian's nginx unit
// reloads with `ExecReload=/usr/sbin/nginx -g '...' -s reload`, and its apache2
// unit with `ExecReload=/usr/sbin/apachectl graceful`, verbatim.
//
// So: the platform's own command wherever one exists, systemctl only where none
// does, and a note saying so on the ones where it does not.
//
// # Why every path is under /etc/certpilot/live
//
// Not inside /etc/nginx or /etc/postfix. Those belong to a package manager and
// to whatever configuration management already writes there; a certificate
// manager that scatters files through them makes somebody else's `dpkg
// --verify` noisy and its own uninstall a hunt. One directory, one owner, and
// a configuration line pointing into it.
//
// The filenames inside it are certbot's — cert.pem, privkey.pem,
// fullchain.pem — because a large number of the people reading this have an
// nginx configuration that already names those files, and changing the spelling
// would earn nothing.
//
// # chain.pem is deliberately not a default anywhere
//
// The installer refuses a destination that asks for a chain when the issued
// certificate came with none, which is correct — a destination asking for a
// file that cannot be produced should say so. But it makes chain_path a bad
// default: it would turn the self-signed gateway, which is what somebody
// evaluating this uses first, into a failed install on their first try.
var catalogue = []Profile{
	{
		Name:     "nginx",
		Platform: "nginx",
		OS:       "linux",
		Summary:  "Serves whatever certificate is on disk; reloads without dropping a connection.",
		Detect: []string{
			"/etc/nginx/nginx.conf",
			"/usr/local/nginx/conf/nginx.conf",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		KeyMode:       "0640",
		Check:         []string{"/usr/sbin/nginx", "-t"},
		Reload:        []string{"/usr/sbin/nginx", "-s", "reload"},
		Notes: []string{
			"ssl_certificate must point at fullchain.pem, not cert.pem. nginx does " +
				"not read chain_path or build a chain itself, so a server block " +
				"naming cert.pem serves the leaf alone — which every browser accepts " +
				"from a cache and no fresh client does.",
			"nginx reloads by starting new workers and letting the old ones finish, " +
				"so no connection is dropped and no request sees a half-written file.",
			"The key is written 0640 with no group, which on a root-owned file is the " +
				"same as 0600 — nginx's master reads the key as root before the workers " +
				"drop privileges, so the worker user never needs it. The mode is 0640 " +
				"rather than 0600 so that adding `\"group\": \"ssl-cert\"` is the only " +
				"change needed on a host that shares the key with something else, " +
				"rather than two changes where forgetting the second one silently does " +
				"nothing.",
		},
		Verified: "nginx 1.27.5",
	},
	{
		Name:     "apache",
		Platform: "Apache httpd",
		OS:       "linux",
		Summary:  "Serves what SSLCertificateFile names; graceful restart finishes in-flight requests.",
		Detect: []string{
			"/etc/apache2/apache2.conf",
			"/etc/httpd/conf/httpd.conf",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		KeyMode:       "0640",
		Check:         []string{"/usr/sbin/apachectl", "configtest"},
		Reload:        []string{"/usr/sbin/apachectl", "graceful"},
		Notes: []string{
			"SSLCertificateFile should name fullchain.pem. Apache 2.4.8 and later read " +
				"the intermediates out of that same file; SSLCertificateChainFile is " +
				"deprecated and is not needed.",
			"`apachectl configtest` opens the certificate — a missing or empty file " +
				"fails the check, which is more than most of the catalogue manages. It " +
				"does not pair the certificate with the key, so a mismatched pair " +
				"passes and fails the handshake. Checked against 2.4.68, not assumed.",
			"apachectl rather than systemctl, because the unit is apache2 on Debian " +
				"and httpd on Red Hat. This is the command Debian's unit runs verbatim " +
				"— ExecReload=/usr/sbin/apachectl graceful — and it is the same on Red " +
				"Hat, where the unit name is not.",
		},
		Verified: "Apache 2.4.68 (Debian package)",
	},
	{
		Name:     "haproxy",
		Platform: "HAProxy",
		OS:       "linux",
		Summary:  "Wants the certificate, the chain and the key concatenated into one file.",
		Detect: []string{
			"/etc/haproxy/haproxy.cfg",
		},
		// The combined layout: one file at the key's mode. The installer
		// recognises cert_path == key_path and writes certificate, chain, then
		// key in that order — which is the order HAProxy expects and the reason
		// this is not simply "PEM with extra steps".
		CertPath: profileDir + "/" + certificatePlaceholder + "/haproxy.pem",
		KeyPath:  profileDir + "/" + certificatePlaceholder + "/haproxy.pem",
		KeyMode:  "0640",
		Check:    []string{"/usr/sbin/haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"},
		Reload:   []string{"/usr/bin/systemctl", "reload", "haproxy"},
		Notes: []string{
			"One file. `bind :443 ssl crt /etc/certpilot/live/<name>/haproxy.pem` reads " +
				"the certificate, the chain and the key out of it, and the installer " +
				"writes them in that order at the key's mode.",
			"systemctl here, unlike the other web servers, because HAProxy has no " +
				"in-process reload of its own: the seamless one hands the listening " +
				"sockets to a new process, and systemd is what holds them. On a host " +
				"without systemd, replace this with whatever starts HAProxy.",
			"If the check command names a different configuration file than this host " +
				"uses, change it. -f is the path HAProxy reads, and validating the " +
				"wrong file is worse than not validating.",
		},
		Verified: "HAProxy 2.6.12 (Debian package)",
	},
	{
		Name:     "caddy",
		Platform: "Caddy",
		OS:       "linux",
		Summary:  "Manages its own certificates by default; this is for the estate where it must not.",
		Detect: []string{
			"/etc/caddy/Caddyfile",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		KeyMode:       "0640",
		Check:         []string{"/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile"},
		Reload:        []string{"/usr/bin/caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--force"},
		Notes: []string{
			"The `tls` directive takes a certificate file and a key file, and the " +
				"certificate file is expected to carry the intermediates — so point it " +
				"at fullchain.pem, not cert.pem, exactly as with nginx.",
			"Set `auto_https off`, or Caddy will go and get its own certificate and " +
				"the one installed here will never be served. This is the commonest " +
				"way for a Caddy deployment to look broken while working perfectly.",
			"--force is not optional, and this profile exists partly to say so. " +
				"Caddy compares the configuration it is handed against the one it is " +
				"running, and a rotated certificate does not change the Caddyfile — so " +
				"a plain `caddy reload` logs \"config is unchanged\", does nothing, and " +
				"exits 0. The install reports success, the certificate on disk is new, " +
				"and the one on the wire is the old one until something restarts Caddy.",
			"`caddy reload` talks to the admin API on localhost:2019. If that is " +
				"disabled, this reload cannot work and a restart is the only option.",
		},
		Verified: "Caddy 2.11.4",
	},
	{
		Name:     "postgresql",
		Platform: "PostgreSQL",
		OS:       "linux",
		Summary:  "Speaks TLS on the same port as everything else, which is why nobody remembers it has a certificate.",
		Detect: []string{
			"/etc/postgresql",
			"/var/lib/pgsql/data/postgresql.conf",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		Owner:         "postgres",
		Group:         "postgres",
		KeyMode:       "0600",
		Reload:        []string{"/usr/bin/systemctl", "reload", "postgresql"},
		Notes: []string{
			"ssl_cert_file should name fullchain.pem and ssl_key_file privkey.pem, " +
				"with ssl = on. PostgreSQL reads both again on reload, so a rotation " +
				"needs no restart and drops no connection.",
			"PostgreSQL is one of the few services that checks: it refuses to start " +
				"if the key is readable by anyone but the account it runs as. That is " +
				"why this profile sets owner, group and 0600 rather than leaving them " +
				"to the defaults — and why a host whose PostgreSQL runs as something " +
				"other than `postgres` has to say so here.",
			"There is no check command, because PostgreSQL has no configuration " +
				"validator to run. What happens instead is better than nothing and " +
				"worth knowing: a postmaster handed an unreadable or malformed " +
				"certificate on reload logs the failure and **carries on with the one " +
				"it already had**. The service does not fall over; the rotation " +
				"silently does not happen. Watch the log after a rotation.",
			"systemctl reload postgresql is Debian's unit. Red Hat's carries the major " +
				"version — postgresql-16 — so change it there.",
		},
		Verified: "PostgreSQL 16.15",
	},
	{
		Name:     "postfix",
		Platform: "Postfix",
		OS:       "linux",
		Summary:  "Presents a certificate to every other mail server on the internet, on port 25.",
		Detect: []string{
			"/etc/postfix/main.cf",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		KeyMode:       "0600",
		Check:         []string{"/usr/sbin/postfix", "check"},
		Reload:        []string{"/usr/sbin/postfix", "reload"},
		Notes: []string{
			"smtpd_tls_cert_file names fullchain.pem and smtpd_tls_key_file privkey.pem. " +
				"Postfix has no separate chain setting for this; the intermediates go in " +
				"the same file as the leaf.",
			"`postfix check` is a real validator and this profile uses it, but be clear " +
				"about what it checks: file ownership, permissions and configuration " +
				"consistency, not whether the certificate and the key are a pair. A " +
				"mismatched pair passes the check and fails the handshake.",
			"`postfix reload` restarts the smtpd processes without stopping the queue. " +
				"Mail in flight is not lost and the listener does not drop.",
			"Postfix runs smtpd as a chrooted, unprivileged process — but the master " +
				"reads the certificate before dropping privileges, so the key does not " +
				"need to be readable by the postfix user and this profile leaves it 0600 " +
				"and root-owned.",
		},
		Verified: "Postfix 3.7.11 (Debian package)",
	},
	{
		Name:     "dovecot",
		Platform: "Dovecot",
		OS:       "linux",
		Summary:  "IMAP and POP3 over TLS — the certificate every mail client in the estate checks.",
		Detect: []string{
			"/etc/dovecot/dovecot.conf",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		KeyMode:       "0600",
		Check:         []string{"/usr/bin/doveconf", "-n"},
		Reload:        []string{"/usr/bin/doveadm", "reload"},
		Notes: []string{
			"Dovecot's syntax for these is a redirection, not a path: " +
				"`ssl_cert = </etc/certpilot/live/<name>/fullchain.pem`. The `<` is " +
				"required and means read the file; without it Dovecot treats the path " +
				"as the certificate itself and fails in a way that reads like a " +
				"corrupt certificate.",
			"`doveconf -n` parses the whole configuration and exits non-zero on a " +
				"syntax error, which is what makes it usable as a check. It does not " +
				"open the certificate — a path that does not exist passes.",
			"A mail client holding an IMAP IDLE connection keeps it across a reload. " +
				"The new certificate is presented to new connections only, so a rotation " +
				"is not visible to the estate until clients reconnect.",
		},
		Verified: "Dovecot 2.3.19.1 (Debian package)",
	},
	{
		Name:     "mariadb",
		Platform: "MariaDB and MySQL",
		OS:       "linux",
		Summary:  "Rotates its certificate without dropping a connection, if you know the statement.",
		Detect: []string{
			"/etc/mysql/mariadb.conf.d",
			"/etc/mysql/my.cnf",
			"/etc/my.cnf.d",
		},
		CertPath:      profileDir + "/" + certificatePlaceholder + "/cert.pem",
		KeyPath:       profileDir + "/" + certificatePlaceholder + "/privkey.pem",
		FullChainPath: profileDir + "/" + certificatePlaceholder + "/fullchain.pem",
		Owner:         "mysql",
		Group:         "mysql",
		KeyMode:       "0600",
		Reload:        []string{"/usr/bin/mariadb", "-e", "FLUSH SSL"},
		Notes: []string{
			"ssl_cert names fullchain.pem and ssl_key privkey.pem, under [mariadbd] " +
				"(or [mysqld]). The server reads them at startup and again on FLUSH SSL.",
			"FLUSH SSL is the whole point of this profile. Before MariaDB 10.4 and " +
				"MySQL 8.0.16 the only way to present a new certificate was a restart, " +
				"and a great many runbooks still say so — which is why database " +
				"certificates get left to expire. On MySQL the statement is spelled " +
				"`ALTER INSTANCE RELOAD TLS`; change this line there.",
			"The reload runs as root over the unix socket, which works on a Debian or " +
				"Ubuntu package because root authenticates with unix_socket. On a host " +
				"where root has a password, this needs credentials — put them in a " +
				"my.cnf the root account reads, never on this command line, where they " +
				"would be visible to `ps` for every account on the machine.",
			"The key must be owned by the account the server runs as, which is why " +
				"this profile sets owner and group to mysql. Get it wrong and MariaDB " +
				"**refuses to start** — \"Failed to setup SSL … Aborting\", checked " +
				"against 10.11 rather than assumed. That is the safe failure and it is " +
				"still an outage, so the ownership here is not cosmetic: a destination " +
				"that writes this key as root is one that takes the database down at " +
				"the next restart, which may be weeks after the rotation that caused " +
				"it.",
		},
		Verified: "MariaDB 10.11.18 (Debian package)",
	},
	{
		Name:     "tomcat",
		Platform: "Apache Tomcat",
		OS:       "linux",
		Summary:  "Reads a PKCS#12 keystore, not PEM — which is why half a Java estate renews by hand.",
		Detect: []string{
			"/etc/tomcat10/server.xml",
			"/etc/tomcat9/server.xml",
			"/opt/tomcat/conf/server.xml",
			"/usr/local/tomcat/conf/server.xml",
		},
		Format:   FormatPKCS12,
		CertPath: profileDir + "/" + certificatePlaceholder + "/keystore.p12",
		KeyMode:  "0640",
		Reload:   []string{"/usr/bin/systemctl", "restart", "tomcat10"},
		Notes: []string{
			"A keystore is one file holding the certificate, its chain and the key, " +
				"so cert_path is that file and key_path is omitted. Point " +
				"certificateKeystoreFile at it with certificateKeystoreType=\"PKCS12\".",
			"keystore_password is required and this profile does not supply one, " +
				"deliberately. The value has to match what server.xml already says, and " +
				"defaulting it to `changeit` — which is what every Java tutorial uses — " +
				"would be theatre with the added harm of looking like protection. Set " +
				"keystore_password or keystore_password_file on the destination.",
			"Restart, not reload. Tomcat re-reads a keystore when the connector is " +
				"rebuilt, and there is no supported command to make it do that in " +
				"place — so this is the one profile in the catalogue whose rotation " +
				"drops connections. Schedule it.",
			"Whatever you put here runs with PATH and nothing else — the agent " +
				"clears the environment before running a check or a reload, so that a " +
				"command from this file cannot read the enrolment token that put the " +
				"agent's own environment together. catalina.sh needs JAVA_HOME and will " +
				"not guess, so a reload that calls it directly must export JAVA_HOME " +
				"itself. Going through systemctl avoids this, because the unit sets it.",
			"The unit is tomcat10 on Debian 12. Change the name for tomcat9, for a " +
				"Red Hat host, or for a Tomcat installed from the tarball rather than " +
				"a package — which is most of them.",
			"PKCS#12 and not JKS: Java 9 made PKCS#12 the default keystore type and " +
				"every JDK since reads it natively. A Java 8 estate, or an application " +
				"with a hard-coded storetype=JKS, is not covered — see #48.",
		},
		Verified: "Apache Tomcat 10.1.59 on JDK 21",
	},
	{
		Name:     "iis",
		Platform: "Microsoft IIS",
		OS:       "windows",
		Summary:  "Binds a certificate by thumbprint out of the machine store, and reads no file at all.",
		Detect: []string{
			`C:\Windows\System32\inetsrv\config\applicationHost.config`,
			`C:\Windows\System32\inetsrv\InetMgr.exe`,
		},
		Store: `LocalMachine\My`,
		Bind: []string{
			`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"-NoProfile", "-NonInteractive", "-Command", iisBind,
		},
		Notes: []string{
			"The https binding has to exist already. This re-points one; it does not " +
				"create sites or bindings, because creating one means choosing a port, an " +
				"address, a host header and whether SNI is on — decisions about how this " +
				"machine serves traffic, which are not a certificate manager's to make. " +
				"Add the binding once in IIS Manager with any certificate; every renewal " +
				"after that is this.",
			"The site is 'Default Web Site'. Change it — that is the name IIS ships " +
				"with and it is not the name most estates use. It appears once, in the " +
				"bind command, which you override by writing your own `bind` on the " +
				"destination.",
			"`$ErrorActionPreference = 'Stop'` is in that command deliberately. Without " +
				"it PowerShell prints a red error, carries on, and exits 0 — so the agent " +
				"would record a binding that never happened and the host would keep " +
				"serving the old certificate until it expired. Keep it in anything you " +
				"write yourself.",
			"Set `verify`. It is the only check this platform has: there is no " +
				"`nginx -t` for a certificate store, so nothing can tell you in advance " +
				"whether a binding will work. With it the agent connects to the endpoint " +
				"after binding and puts the binding back if the certificate being served " +
				"is not the one it just installed. This profile does not set it because " +
				"the port is a property of your site, and a default that guessed wrong " +
				"would roll back a good certificate on every renewal.",
			"The private key is imported non-exportable, which is what makes \"the key " +
				"never leaves the host\" a property rather than a hope. An Exchange DAG " +
				"or an ADFS farm that needs the same key on several nodes cannot use " +
				"this; enrol each node and give each its own certificate.",
			"Intermediates go into LocalMachine\\CA, because schannel builds the chain " +
				"it sends from there rather than from whatever arrived beside the leaf. A " +
				"self-signed root in the chain is imported nowhere: that store is Root, " +
				"and adding to it makes a certificate authority trusted by every program " +
				"on the machine, which is an administrator's decision and not a side " +
				"effect of a renewal.",
			"The certificate this one replaces is removed once the new one is bound and " +
				"verified. The agent finds it by the friendly name it gave it — " +
				"\"CertPilot: <destination>\", which is the Friendly Name column in " +
				"certlm.msc — so renaming one there means the agent no longer recognises " +
				"it and will leave it behind rather than remove something it is no longer " +
				"sure about.",
			"Exchange, ADFS, Network Policy Server and Remote Desktop Services import " +
				"from the same store and differ only in the binding step, so each is this " +
				"profile with its own `bind` — Exchange, for instance, is " +
				"`Enable-ExchangeCertificate -Thumbprint '{{ .Thumbprint }}' -Services " +
				"IIS,SMTP`. None of the four has been run by this project, and they are " +
				"listed here as a shape to copy rather than as a supported platform.",
		},
		Verified: "IIS 10.0 on Windows Server 2025",
	},
}

// iisBind is the command that re-points an IIS site at a newly imported
// certificate.
//
// One line of PowerShell rather than something compiled in, because the agent
// deliberately knows nothing about IIS: what it knows is how to import a
// certificate and how to run the command this host's administrator wrote down.
// This is that command, supplied so the common case is one word.
//
// Three things in it are load-bearing and easy to drop when copying it.
//
// $ErrorActionPreference is first because PowerShell's default is to print an
// error and keep going. A bind that failed would exit 0, the agent would record
// a success, and the host would serve the old certificate until it expired —
// the exact silent failure this whole package is built to prevent.
//
// The loop, because a site can have several https bindings and Get-WebBinding
// returns all of them. Binding the first and leaving the rest is how one
// hostname renews for years while another quietly does not.
//
// And the sslFlags test, because the method differs. A binding with SNI on is
// keyed by host header and takes AddSslCertificateByHostHeader; one without is
// keyed by address and port and takes AddSslCertificate. Calling the wrong one
// fails, and the presence of a host header is not the discriminator — sslFlags
// is.
const iisBind = `$ErrorActionPreference = 'Stop'; ` +
	`Import-Module WebAdministration; ` +
	`$site = 'Default Web Site'; ` +
	`$bindings = @(Get-WebBinding -Name $site -Protocol https); ` +
	`if ($bindings.Count -eq 0) { throw "$site has no https binding to re-point" }; ` +
	`foreach ($b in $bindings) { ` +
	`if (([int]$b.sslFlags -band 1) -eq 1) ` +
	`{ $b.AddSslCertificateByHostHeader('{{ .Thumbprint }}', 'My') } ` +
	`else { $b.AddSslCertificate('{{ .Thumbprint }}', 'My') } ` +
	`}`
