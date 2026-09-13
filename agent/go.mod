module github.com/certpilot/certpilot/agent

go 1.26.6

replace github.com/certpilot/certpilot/pkg => ../pkg

require (
	github.com/certpilot/certpilot/pkg v0.0.0
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require golang.org/x/crypto v0.55.0 // indirect
