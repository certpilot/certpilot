# syntax=docker/dockerfile:1

# The control plane.
#
# Built from the repository root because this is a Go workspace: core/go.mod
# carries `replace github.com/certpilot/certpilot/pkg => ../pkg`, which a
# context rooted at core/ cannot resolve. .dockerignore keeps the context to
# source — and keeps .env and .certpilot/ out of the builder layer.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src
COPY . .

# Set by buildx, one pair per platform being built. Declared after COPY so the
# source layer is shared between architectures rather than invalidated per-arch.
ARG TARGETOS
ARG TARGETARCH

# CGO off: the runtime stage is alpine and a cgo-linked binary would pick up a
# glibc dependency the image does not have. -trimpath keeps the build machine's
# paths out of the binary.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/certpilot-core ./core/cmd/

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S certpilot && adduser -S -G certpilot -h /app certpilot

WORKDIR /app
COPY --from=builder /out/certpilot-core /app/certpilot-core
COPY config.example.yaml /app/config.example.yaml

# Shipped so `certpilot-core --migrate` works from the image. The server never
# applies them itself; this is here for the operator who runs migrations as a
# one-off job or an init container.
COPY migrations /app/migrations

# Created here so that a named volume mounted at this path inherits certpilot's
# ownership rather than root's. Docker seeds an empty volume from the image
# directory it covers, permissions included — and without this, the quickstart's
# `certs` service runs as uid 100 against a root-owned directory and cannot
# write the mTLS material it exists to write.
RUN mkdir -p /app/pki && chown certpilot:certpilot /app/pki

USER certpilot

EXPOSE 8080

ENTRYPOINT ["/app/certpilot-core"]
CMD ["--config=/app/config.example.yaml"]
