# Stage 1: Build
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o maknoon ./cmd/maknoon

# Stage 2: Prepare minimal OS layout with correct permissions
FROM alpine:3.21 AS layout
RUN mkdir -p /tmp/maknoon && chmod 1777 /tmp && chown 1000:1000 /tmp/maknoon
RUN mkdir -p /home/maknoon && chown 1000:1000 /home/maknoon

# Stage 3: Final Secure Sandbox
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=layout /etc/passwd /etc/passwd
COPY --from=layout /etc/group /etc/group
COPY --from=layout --chown=1000:1000 /tmp /tmp
COPY --from=layout --chown=1000:1000 /home/maknoon /home/maknoon

COPY --from=builder /app/maknoon /usr/local/bin/maknoon

WORKDIR /home/maknoon
ENV HOME=/home/maknoon
USER 1000:1000

ENTRYPOINT ["/usr/local/bin/maknoon"]
CMD ["mcp"]
