// The contract between a host agent and the core.
//
// Separate from the gateway SDK because they share nothing: an agent speaks
// HTTP with a signature and never imports the provider proto. Two extension
// points that happened to live in one directory.
//
// The module path is the repository this will live in, for the same reason as
// the gateway SDK's.
module github.com/certpilot/certpilot-agent-sdk

go 1.26.6
