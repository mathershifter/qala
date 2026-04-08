# ── Build stage ──
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache dependencies separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# modernc.org/sqlite is pure Go — no CGo needed.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /seacrt ./cmd/seacrt

# ── Run stage ──
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /seacrt /usr/local/bin/seacrt
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# /data holds CA keys, certs, and the SQLite database.
# Mount a volume here to persist state across container restarts.
VOLUME /data

ENV SEACRT_DATA_DIR=/data \
    SEACRT_ADDR=0.0.0.0:8080 \
    SEACRT_LOG_LEVEL=info

EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
