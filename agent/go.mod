module github.com/certpilot/certpilot/agent

go 1.26.6

replace github.com/certpilot/certpilot/pkg => ../pkg

replace github.com/certpilot/certpilot-gateway-sdk => ../pkg/gatewaysdk

replace github.com/certpilot/certpilot-agent-sdk => ../pkg/agentsdk

require (
	github.com/certpilot/certpilot-agent-sdk v0.0.0-00010101000000-000000000000
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require golang.org/x/crypto v0.55.0 // indirect
