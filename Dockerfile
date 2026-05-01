# Stage 1: Build
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o maknoon ./cmd/maknoon

# Stage 2: Layout
FROM alpine:3.21 AS layout
RUN mkdir -p /tmp/maknoon && chmod 1777 /tmp && chown 1000:1000 /tmp/maknoon
RUN mkdir -p /home/maknoon && chown 1000:1000 /home/maknoon

# Stage 3: Final Secure Sandbox
FROM scratch

# OCI Annotations (Industry Standard Metadata)
LABEL org.opencontainers.image.title="Maknoon" \
      org.opencontainers.image.description="Industrial-Grade Post-Quantum Encryption Engine and MCP Server" \
      org.opencontainers.image.vendor="al-Zamakhshari" \
      org.opencontainers.image.source="https://github.com/al-Zamakhshari/maknoon" \
      org.opencontainers.image.licenses="MIT"

# Import system artifacts
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=layout /etc/passwd /etc/passwd
COPY --from=layout /etc/group /etc/group
COPY --from=layout --chown=1000:1000 /tmp /tmp
COPY --from=layout --chown=1000:1000 /home/maknoon /home/maknoon

# Copy binary
COPY --from=builder /app/maknoon /usr/local/bin/maknoon

WORKDIR /home/maknoon
ENV HOME=/home/maknoon
USER 1000:1000

# Define persistent storage locations
VOLUME ["/home/maknoon"]

# Default to MCP Stdio, but ready for SSE
CMD ["maknoon", "mcp"]
