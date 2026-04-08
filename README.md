# qala

A lightweight Certificate Signing Service for lab environments. Runs a two-tier CA (Root + Intermediate) and exposes a REST API and CLI for issuing TLS server and mTLS client certificates. All state is stored in a single SQLite database — no external dependencies required.

## Contents

- [Quick Start](#quick-start)
- [Building](#building)
- [Running with Docker](#running-with-docker)
- [CLI Reference](#cli-reference)
- [REST API Reference](#rest-api-reference)
- [Configuration](#configuration)
- [File Layout](#file-layout)

---

## Quick Start

```sh
# 1. Initialize the CA (run once)
qala init

# 2. Start the server
qala serve

# 3. Issue a server certificate
qala sign server --cn api.lab --dns api.lab --dns api --ip 10.0.0.10 --out ./certs/api

# 4. Issue a client auth certificate
qala sign client --cn alice --out ./certs/alice

# 5. Trust the CA in your environment
qala ca-chain --out /usr/local/share/ca-certificates/qala.pem
```

---

## Building

Requires Go 1.22+. No CGo — the binary is fully statically linked.

```sh
go build -o qala ./cmd/qala
```

Compile for Linux + trim paths + strip symbols and DWARF:

```sh
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o qala ./cmd/qala
```

---

## Running with Docker

The Docker image handles `init` automatically on first start. Mount a volume at `/data` to persist the CA and database across container restarts.

```sh
# First run: initializes CA, then starts the server
docker run -d \
  --name qala \
  -v qala-data:/data \
  -p 8080:8080 \
  qala:latest

# Use the CLI against a running container
docker exec qala qala sign server \
  --cn api.lab \
  --dns api.lab \
  --api-url http://localhost:8080
```

Build the image:

```sh
docker build -t qala:latest .
```

Environment variables supported in Docker (see [Configuration](#configuration)):

| Variable | Default |
|---|---|
| `QALA_DATA_DIR` | `/data` |
| `QALA_ADDR` | `0.0.0.0:8080` |
| `QALA_LOG_LEVEL` | `info` |

---

## CLI Reference

All commands share these global flags:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--data-dir` | `QALA_DATA_DIR` | `./data` | CA keys, certs, and SQLite database |
| `--log-level` | `QALA_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `--api-url` | `QALA_API_URL` | `http://localhost:8080` | Server URL for client commands |

---

### `qala init`

Generates the Root CA and Intermediate CA key pairs and certificates. Run once before starting the server.

```sh
qala init [--data-dir ./data]
```

Output files written to `--data-dir`:

```
root-ca.key.pem           Root CA private key  (keep offline after init)
root-ca.cert.pem          Root CA certificate
intermediate-ca.key.pem   Intermediate CA private key
intermediate-ca.cert.pem  Intermediate CA certificate
```

Returns an error if the CA files already exist.

---

### `qala serve`

Starts the REST API server. Requires the CA to be initialized first.

```sh
qala serve [--data-dir ./data] [--addr 0.0.0.0:8080]
```

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--addr` | `QALA_ADDR` | `0.0.0.0:8080` | Listen address |

```sh
# Listen on a non-default port
qala serve --addr 127.0.0.1:9000

# Debug logging
qala serve --log-level debug
```

Handles `SIGINT` and `SIGTERM` with a 10-second graceful drain.

---

### `qala sign server`

Issues a TLS server certificate. Requires at least one DNS name or IP address.

```sh
qala sign server --cn <common-name> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--cn` | (required) | Certificate common name |
| `--dns` | | DNS SAN — repeatable |
| `--ip` | | IP SAN — repeatable |
| `--algo` | `ecdsa` | Key algorithm: `ecdsa` or `rsa` |
| `--days` | `90` | Validity in days (1–365) |
| `--out` | `.` | Output directory for PEM files |
| `--reuse` | `false` | Retrieve existing cert if CN is already active |

Output files written to `--out`:

| File | Mode | Contents |
|---|---|---|
| `cert.pem` | 0644 | Signed certificate |
| `key.pem` | 0600 | Private key (PKCS8 PEM) |
| `chain.pem` | 0644 | Intermediate + Root CA chain |

**Examples:**

```sh
# DNS SAN only
qala sign server --cn api.lab --dns api.lab --out ./certs/api

# Multiple DNS names
qala sign server --cn api.lab --dns api.lab --dns api --out ./certs/api

# DNS and IP SANs
qala sign server --cn api.lab --dns api.lab --ip 10.0.0.10 --out ./certs/api

# RSA key, 30-day validity
qala sign server --cn api.lab --dns api.lab --algo rsa --days 30 --out ./certs/api

# Retrieve existing cert instead of erroring on duplicate CN
qala sign server --cn api.lab --dns api.lab --reuse --out ./certs/api
```

If an active certificate already exists for the CN, the command exits with an error. Pass `--reuse` to retrieve the existing certificate and key instead.

---

### `qala sign client`

Issues a client authentication (mTLS) certificate.

```sh
qala sign client --cn <identity> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--cn` | (required) | Client identity (e.g. username or service name) |
| `--algo` | `ecdsa` | Key algorithm: `ecdsa` or `rsa` |
| `--days` | `90` | Validity in days (1–365) |
| `--out` | `.` | Output directory for PEM files |
| `--reuse` | `false` | Retrieve existing cert if CN is already active |

**Examples:**

```sh
# Issue a cert for user "alice"
qala sign client --cn alice --out ./certs/alice

# Issue for a service account
qala sign client --cn worker-svc --out ./certs/worker

# 365-day cert with RSA key
qala sign client --cn alice --algo rsa --days 365 --out ./certs/alice

# Retrieve existing cert if already issued
qala sign client --cn alice --reuse --out ./certs/alice
```

---

### `qala list`

Lists issued certificates.

```sh
qala list [--type server|client] [--expired]
```

| Flag | Description |
|---|---|
| `--type` | Filter by `server` or `client` |
| `--expired` | Include expired certificates (default: active only) |

**Examples:**

```sh
# List all active certificates
qala list

# List only server certificates
qala list --type server

# List all client certificates including expired ones
qala list --type client --expired
```

Sample output:

```
SERIAL                             TYPE    COMMON NAME   ISSUED      EXPIRES
3a2f1b...                          server  api.lab       2026-04-01  2026-06-30
9b1cde...                          client  alice         2026-04-01  2026-06-30

Total: 2
```

---

### `qala delete`

Deletes a certificate record by serial. The serial is shown in `qala list` output and is returned by all sign responses.

```sh
qala delete <serial>
```

**Examples:**

```sh
# Delete by serial
qala delete 3a2f1b...

# Common pattern: look up the serial first, then delete
qala list --type server
qala delete 3a2f1b...
```

After deletion the CN is free to be re-issued. There is no revocation — if the certificate was distributed to clients, remove it from those trust stores separately.

---

### `qala ca-chain`

Fetches the CA certificate chain (Intermediate + Root) from the server.

```sh
qala ca-chain [--out <file>]
```

| Flag | Description |
|---|---|
| `--out` | Write to file instead of stdout |

**Examples:**

```sh
# Print to stdout
qala ca-chain

# Save to file
qala ca-chain --out /etc/ssl/certs/qala-chain.pem

# Trust on Debian/Ubuntu
qala ca-chain --out /usr/local/share/ca-certificates/qala.crt
sudo update-ca-certificates

# Trust on RHEL/Fedora
qala ca-chain --out /etc/pki/ca-trust/source/anchors/qala.pem
sudo update-ca-trust
```

---

## REST API Reference

Base URL: `http://<host>:8080`

All request and response bodies are JSON. Certificates and keys are PEM-encoded strings within the JSON.

---

### `GET /health`

```sh
curl http://localhost:8080/health
```

```json
{"status": "ok"}
```

---

### `GET /ca-chain`

Returns the Intermediate + Root CA certificate chain.

```sh
curl http://localhost:8080/ca-chain
```

```json
{
  "chain_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

---

### `POST /sign/server`

Issues a TLS server certificate. Returns `409 Conflict` with the existing serial if an active certificate already exists for the CN.

```sh
curl -s -X POST http://localhost:8080/sign/server \
  -H 'Content-Type: application/json' \
  -d '{
    "common_name": "api.lab",
    "dns_names": ["api.lab", "api"],
    "ip_addresses": ["10.0.0.10"],
    "key_algorithm": "ecdsa",
    "validity_days": 90
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `common_name` | string | yes | Certificate CN |
| `dns_names` | []string | no | DNS SANs |
| `ip_addresses` | []string | no | IP SANs |
| `key_algorithm` | string | no | `ecdsa` (default) or `rsa` |
| `validity_days` | int | no | 1–365, default 90 |

At least one of `dns_names` or `ip_addresses` is required.

**Response `201 Created`:**

```json
{
  "serial": "3a2f1b...",
  "type": "server",
  "common_name": "api.lab",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "issued_at": "2026-04-01T12:00:00Z",
  "expires_at": "2026-06-30T12:00:00Z"
}
```

**Response `409 Conflict`** (CN already has an active certificate):

```json
{
  "error": "active certificate already exists for this common name: cn=\"api.lab\" serial=3a2f1b...",
  "serial": "3a2f1b..."
}
```

Use the `serial` to retrieve the existing certificate via `GET /certs/{serial}`.

---

### `POST /sign/client`

Issues a client authentication certificate.

```sh
curl -s -X POST http://localhost:8080/sign/client \
  -H 'Content-Type: application/json' \
  -d '{
    "common_name": "alice",
    "key_algorithm": "ecdsa",
    "validity_days": 90
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `common_name` | string | yes | Client identity |
| `key_algorithm` | string | no | `ecdsa` (default) or `rsa` |
| `validity_days` | int | no | 1–365, default 90 |

**Response `201 Created`:** Same shape as `POST /sign/server`.

**Response `409 Conflict`:** Same shape as `POST /sign/server`.

---

### `GET /certs`

Lists issued certificates. Returns summaries (no PEM data).

```sh
# All active certificates
curl http://localhost:8080/certs

# Filter by type
curl "http://localhost:8080/certs?type=server"

# Include expired
curl "http://localhost:8080/certs?expired=true"

# Pagination
curl "http://localhost:8080/certs?limit=20&offset=40"
```

| Param | Description |
|---|---|
| `type` | `server` or `client` |
| `expired` | `true` to include expired (default: active only) |
| `limit` | Max results (default: 100) |
| `offset` | Pagination offset (default: 0) |

**Response `200 OK`:**

```json
{
  "certs": [
    {
      "serial": "3a2f1b...",
      "type": "server",
      "common_name": "api.lab",
      "issued_at": "2026-04-01T12:00:00Z",
      "expires_at": "2026-06-30T12:00:00Z"
    }
  ],
  "total": 1
}
```

---

### `GET /certs/{serial}`

Returns the full certificate record including the private key.

```sh
curl http://localhost:8080/certs/3a2f1b...
```

**Response `200 OK`:** Full `IssuedCert` object (same shape as the sign response).

---

### `GET /certs/by-cn`

Returns the active certificate for a CN without knowing its serial. Includes the private key.

```sh
# Look up a server certificate by CN
curl "http://localhost:8080/certs/by-cn?type=server&cn=api.lab"

# Look up a client certificate
curl "http://localhost:8080/certs/by-cn?type=client&cn=alice"
```

| Param | Required | Description |
|---|---|---|
| `type` | yes | `server` or `client` |
| `cn` | yes | The common name to look up |

**Response `200 OK`:** Full `IssuedCert` object. Returns `404` if no active certificate exists for the CN.

---

### `DELETE /certs/{serial}`

Deletes a certificate record. After deletion the CN is free to be re-issued.

```sh
curl -s -X DELETE http://localhost:8080/certs/3a2f1b...
```

**Response `204 No Content`** on success. No body.

**Response `404 Not Found`** if the serial does not exist.

---

### Error responses

All errors return:

```json
{"error": "error-description"}
```

Conflict responses (`409`) additionally include `"serial"`.

| Status | Description |
|---|---|
| `204` | Delete successful |
| `400` | Invalid request (missing fields, bad values) |
| `404` | Certificate not found |
| `409` | Active certificate already exists for this CN |
| `500` | Internal server error |

---

## Configuration

All settings can be provided as flags or environment variables.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--data-dir` | `QALA_DATA_DIR` | `./data` | CA keys, certs, and database |
| `--addr` | `QALA_ADDR` | `0.0.0.0:8080` | Server listen address |
| `--log-level` | `QALA_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `--api-url` | `QALA_API_URL` | `http://localhost:8080` | Server URL for CLI client commands |

---

## File Layout

```
<data-dir>/                   Default: ./data
  root-ca.key.pem             Root CA private key  ← keep offline
  root-ca.cert.pem            Root CA certificate
  intermediate-ca.key.pem     Intermediate CA private key
  intermediate-ca.cert.pem    Intermediate CA certificate
  qala.db                   SQLite database (cert records + private keys)
```
