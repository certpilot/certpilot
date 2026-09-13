.PHONY: test-store all build build-core build-agent build-gateways test test-frontend test-coverage lint proto proto-lint routes \
        dev dev-certs generate-kek run-core run-gateway-selfsigned run-gateway-acme run-gateway-vault run-frontend \
        clean help

# ── Variables ────────────────────────────────────────────
GO   := go
BUF  := buf
BIN  := bin
PKI  := .certpilot/pki
STATE := .certpilot/state

# Each component is its own Go module, so tooling has to iterate rather than
# rely on a single ./... from the repository root.
MODULES := pkg pkg/gatewaysdk pkg/agentsdk core gateways/selfsigned gateways/acme gateways/vault agent

CORE_BIN          := $(BIN)/certpilot-core
GW_SELFSIGNED_BIN := $(BIN)/gateway-selfsigned
GW_ACME_BIN       := $(BIN)/gateway-acme
GW_VAULT_BIN      := $(BIN)/gateway-vault
AGENT_BIN         := $(BIN)/certpilot-agent

# ── Build ────────────────────────────────────────────────
all: proto build

build: build-core build-gateways build-agent

build-core:
	$(GO) build -o $(CORE_BIN) ./core/cmd/

build-agent:
	$(GO) build -o $(AGENT_BIN) ./agent/cmd/

build-gateways: build-gateway-selfsigned build-gateway-acme build-gateway-vault

build-gateway-selfsigned:
	$(GO) build -o $(GW_SELFSIGNED_BIN) ./gateways/selfsigned/cmd/

build-gateway-acme:
	$(GO) build -o $(GW_ACME_BIN) ./gateways/acme/cmd/

build-gateway-vault:
	$(GO) build -o $(GW_VAULT_BIN) ./gateways/vault/cmd/

# ── Proto ────────────────────────────────────────────────
proto:
	$(BUF) generate

proto-lint:
	$(BUF) lint

# ── Setup ────────────────────────────────────────────────

## Generate a key encryption key. Certificate private keys and CA credentials
## are sealed with it before they reach the database.
generate-kek: build-core
	@$(CORE_BIN) --generate-kek

## Generate development mTLS material for the core-to-gateway channel.
## That channel carries CSRs, private keys, and CA credentials, so it is
## mutually authenticated by default; this makes turning it on a single command.
dev-certs: build-core
	@$(CORE_BIN) --generate-dev-certs=$(PKI)

## Apply outstanding database migrations. Reads CERTPILOT_DB_URL (or DATABASE_URL);
## override with `make migrate DB=postgres://...`.
##
## Deliberately not run by the server on startup: a schema change should be
## something an operator decides to do, not a side effect of a replica restarting
## mid-deploy while older replicas are still reading the old shape.
migrate: build-core
	@$(CORE_BIN) --migrate $(if $(DB),--db=$(DB),)

# ── Run (Development) ───────────────────────────────────
#
# Each of these runs in its own terminal. Run `make dev-certs` first.

## Start PostgreSQL, the local gateway, the API, and the frontend in one
## terminal, migrating the database first. Export CERTPILOT_DB_URL to use a
## database of your own instead of the local certpilot_dev one.
dev:
	./scripts/dev.sh

## Fill a running CertPilot with a realistic estate: a CA hierarchy, certificates
## across the whole expiry range, metadata fields of every type, and values on
## every certificate. Idempotent, and deletes nothing.
seed:
	./scripts/seed-demo.sh

## Regenerate docs/routes.json from the router and the handlers. The
## documentation site is built from it, so it is checked in CI — a new route
## with a stale inventory fails.
##
## Two passes, because they read different things. extract-routes reads the
## router: what exists, and who may call it. schemagen reads the handlers:
## what to send, what comes back, and which refusals are possible. Neither
## question is answerable from the other file.
routes:
	python3 scripts/extract-routes.py docs/routes.json
	$(GO) run scripts/schemagen/main.go docs/routes.json

run-core:
	$(GO) run ./core/cmd/ --config=config.dev.yaml

run-gateway-selfsigned:
	$(GO) run ./gateways/selfsigned/cmd/ \
		--port=9091 \
		--tls-cert=$(PKI)/gateway.pem \
		--tls-key=$(PKI)/gateway-key.pem \
		--tls-ca=$(PKI)/ca.pem

run-gateway-acme:
	$(GO) run ./gateways/acme/cmd/ \
		--port=9092 \
		--directory=letsencrypt-staging \
		--state-dir=$(STATE)/acme \
		--tls-cert=$(PKI)/gateway.pem \
		--tls-key=$(PKI)/gateway-key.pem \
		--tls-ca=$(PKI)/ca.pem

## The Vault gateway takes no credential of its own. Each CA account carries
## the AppRole or Kubernetes identity it issues under, so nothing here is
## authorised to sign anything.
run-gateway-vault:
	$(GO) run ./gateways/vault/cmd/ \
		--port=9093 \
		--address=$(VAULT_ADDR) \
		--tls-cert=$(PKI)/gateway.pem \
		--tls-key=$(PKI)/gateway-key.pem \
		--tls-ca=$(PKI)/ca.pem

run-frontend:
	cd frontend && npm run dev

# ── Test ─────────────────────────────────────────────────
test:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) test ./... -cover) || exit 1; \
	done

## test-store runs the store conformance suite against a real PostgreSQL.
##
## The same assertions run against the in-memory store on every `make test`.
## This adds the implementation that has produced every defect the unit tests
## could not express: constraints, column lists, NULL, and type inference.
##
## Either of these gives it a server:
##
##   docker compose -f deploy/plain-postgres/docker-compose.yml up -d
##   make test-store
##
##   brew services start postgresql@17
##   make test-store DB="postgres://$$(whoami)@127.0.0.1:5432/postgres?sslmode=disable"
##
## It creates and drops a database per test, so point it at something
## throwaway. The harness refuses the obvious production hostnames, which is a
## guard rather than a control.
TEST_DB ?= postgres://postgres:conformance@127.0.0.1:55432/postgres?sslmode=disable

test-store:
	@CERTPILOT_TEST_DB_URL="$(if $(DB),$(DB),$(TEST_DB))" \
		$(GO) test ./core/store/ -count=1 -v -run 'Conformance|TestEveryValue|TestAnUnset|TestAnUpdateKeeps|TestABindingKeeps|TestAnEmptyResult|TestTheDeploymentQueue|TestAnAgentTarget'

test-race:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) test ./... -race) || exit 1; \
	done

## Typecheck the frontend and run its checks.
## Needs Node 22.18+ — the checks import TypeScript directly, using Node's own
## type stripping rather than adding a test runner to the dependency tree.
test-frontend:
	cd frontend && npx vue-tsc --noEmit \
		&& node scripts/check-sse.mjs \
		&& node scripts/check-chain.mjs \
		&& node scripts/check-display-token.mjs

test-coverage:
	@for m in $(MODULES); do \
		(cd $$m && $(GO) test ./... -coverprofile=coverage.out && $(GO) tool cover -func=coverage.out | tail -1); \
	done

lint:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) vet ./...) || exit 1; \
	done
	@## The build tools are outside every module, so the loop above never sees
	@## them. schemagen decides what the published API reference says about
	@## request bodies; it rotting silently is the same failure as the docs
	@## rotting silently, which is what it exists to prevent.
	@echo "==> scripts"
	@$(GO) vet scripts/schemagen/main.go
	@gofmt -l $(MODULES) scripts | grep . && echo "gofmt needed on the files above" && exit 1 || true
	@## The three modules under pkg/ must not import each other. Nothing else
	@## enforces it while they share a tree, and the seam closes the first time
	@## somebody reaches across it.
	@echo "==> sdk seam"
	@./scripts/check-sdk-seam.sh
	@## staticcheck when it is installed, because it catches a class go vet does
	@## not: dead assignments, impossible conditions, and code nothing reaches.
	@## Not a hard requirement, so a clone can be linted without installing it.
	@##   go install honnef.co/go/tools/cmd/staticcheck@latest
	@if command -v staticcheck >/dev/null 2>&1; then \
		for m in $(MODULES); do \
			echo "==> staticcheck $$m"; \
			(cd $$m && staticcheck ./...) || exit 1; \
		done; \
	else \
		echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

tidy:
	@for m in $(MODULES); do (cd $$m && $(GO) mod tidy); done

# ── Clean ────────────────────────────────────────────────
clean:
	rm -rf $(BIN)/
	rm -f coverage.out coverage.html
	@for m in $(MODULES); do rm -f $$m/coverage.out; done

## Also removes development keys and ACME account state.
clean-all: clean
	rm -rf .certpilot/

# ── Help ─────────────────────────────────────────────────
help:
	@echo "CertPilot"
	@echo ""
	@echo "Setup"
	@echo "  make dev-certs               Generate development mTLS material"
	@echo "  make generate-kek            Print a new CERTPILOT_KEK"
	@echo ""
	@echo "Build"
	@echo "  make build                   Build all binaries"
	@echo "  make proto                   Generate protobuf Go code"
	@echo ""
	@echo "Run (one per terminal)"
	@echo "  make dev                      Start the complete local development stack"
	@echo "  make run-core                CertPilot Core        :8080"
	@echo "  make run-gateway-selfsigned  Self-signed gateway   :9091"
	@echo "  make run-gateway-acme        ACME gateway          :9092"
	@echo "  make run-gateway-vault       Vault PKI gateway     :9093"
	@echo "  make run-frontend            Vue frontend          :3000"
	@echo ""
	@echo "Docs"
	@echo "  make routes                  Regenerate docs/routes.json from the router"
	@echo ""
	@echo "Check"
	@echo "  make test                    Run all tests"
	@echo "  make test-race               Run all tests under the race detector"
	@echo "  make test-frontend           Typecheck the UI and check the SSE parser"
	@echo "  make lint                    go vet and gofmt"
	@echo ""
	@echo "Clean"
	@echo "  make clean                   Remove build artifacts"
	@echo "  make clean-all               Also remove development keys and ACME state"
