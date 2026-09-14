# syntax=docker/dockerfile:1

# The host agent.
#
# Worth stating plainly, because the image invites the opposite assumption: an
# agent in a container inventories *that container's* filesystem. It is useful
# for enrolling a containerised workload or for exercising the agent protocol,
# and it is not a way to inventory the host it runs on unless the paths you care
# about are mounted into it.
#
# The agent generates its identity key inside its own state directory and sends
# no private key anywhere, so that directory must be a volume or enrolment is
# repeated on every restart.
#
# The build context is the agent module, not the repository root.
#
# It used to be the root, because this repository is a Go workspace and the
# agent's go.mod carried a replace pointing at ../pkg — so a build that could
# not see the sibling could not resolve the module. That replace was dead: the
# agent requires nothing from this repository and imports nothing from it, and
# the directive outlived whatever once needed it.
#
# Building from the module is not tidiness. It is the difference between an
# image whose inputs are the agent and one whose inputs are every file in the
# repository, which means a frontend change invalidating the agent's build cache
# and a context upload measured in the wrong units.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src
COPY . .

# Set by buildx, one pair per platform being built. Declared after COPY so the
# source layer is shared between architectures rather than invalidated per-arch.
ARG TARGETOS
ARG TARGETARCH

# The version this build reports. Left empty for an ordinary build, which then
# keeps the -dev default compiled into the source — an unstamped build saying so
# is better than one claiming to be the release it was branched from.
ARG VERSION=

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w ${VERSION:+-X github.com/certpilot/certpilot/agent.Version=$VERSION}" \
      -o /out/certpilot-agent ./cmd/

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S certpilot && adduser -S -G certpilot -h /app certpilot

WORKDIR /app
COPY --from=builder /out/certpilot-agent /app/certpilot-agent

USER certpilot

# A subcommand CLI — enrol, run, status, scan, request, install — so there is no
# port to expose and no default worth guessing. `run` needs an enrolment that
# already happened, which is why the entrypoint stops at the binary.
ENTRYPOINT ["/app/certpilot-agent"]
CMD ["--help"]
