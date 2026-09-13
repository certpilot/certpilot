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
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src
COPY . .

# Set by buildx, one pair per platform being built. Declared after COPY so the
# source layer is shared between architectures rather than invalidated per-arch.
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/certpilot-agent ./agent/cmd/

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
