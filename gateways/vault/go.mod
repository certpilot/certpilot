module github.com/certpilot/certpilot/gateways/vault

go 1.26.6

replace github.com/certpilot/certpilot/pkg => ../../pkg

replace github.com/certpilot/certpilot-gateway-sdk => ../../pkg/gatewaysdk

replace github.com/certpilot/certpilot-agent-sdk => ../../pkg/agentsdk

require (
	github.com/certpilot/certpilot-gateway-sdk v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
