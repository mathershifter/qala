# qala

A lightweight Certificate Signing Service for lab environments. Runs a two-tier CA (Root + Intermediate) and exposes a REST API and CLI for issuing TLS server and mTLS client certificates. All state is stored in a single SQLite database — no external dependencies required.

## Contents

- [Quick Start](#quick-start)
- [Building](#building)
- [Running with Docker](#running-with-docker)
- [CLI Reference](#cli-reference)
  - [qala init](#qala-init)
  - [qala serve](#qala-serve)
  - [qala sign server](#qala-sign-server)
  - [qala sign client](#qala-sign-client)
  - [qala get](#qala-get)
  - [qala list](#qala-list)
  - [qala delete](#qala-delete)
  - [qala revoke](#qala-revoke)
  - [qala ca-chain](#qala-ca-chain)
  - [qala crl](#qala-crl)
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

Requires Go 1.26+. No CGo — the binary is fully statically linked.

```sh
go build -o qala ./cmd/qala
```

Compile for Linux + trim paths + strip symbols and DWARF:

```sh
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o qala ./cmd/qala
```

---

## Running with Docker

The Docker image is published to `ghcr.io` and handles `init` automatically on first start. Mount a volume at `/data` to persist the CA and database across container restarts.

```sh
# Pull and run from the registry
docker run -d \
  --name qala \
  -v qala-data:/data \
  -p 8080:8080 \
  ghcr.io/jmather/qala:latest

# Use the CLI against a running container
docker exec qala qala sign server \
  --cn api.lab \
  --dns api.lab \
  --api-url http://localhost:8080
```

Build the image locally:

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

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--ca-org` | `QALA_CA_ORG` | `Qala CA` | Organization name in Root CA and Intermediate CA subjects |
| `--ca-cn-root` | `QALA_CA_CN_ROOT` | `Qala Root CA` | Common name for Root CA |
| `--ca-cn-intermediate` | `QALA_CA_CN_INTERMEDIATE` | `Qala Intermediate CA` | Common name for Intermediate CA |
| `--cert-org` | `QALA_CERT_ORG` | `Qala Default OU` | Default Organization for issued leaf certificates |
| `--default-validity-days` | `QALA_DEFAULT_VALIDITY_DAYS` | `365` | Default validity days for issued certificates (1–365) |

Output files written to `--data-dir`:

```
root-ca.key.pem           Root CA private key  (keep offline after init)
root-ca.cert.pem          Root CA certificate
intermediate-ca.key.pem   Intermediate CA private key
intermediate-ca.cert.pem  Intermediate CA certificate
config.json               Operational config read by serve
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
| `--days` | `365` | Validity in days (1–365) |
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
| `--days` | `365` | Validity in days (1–365) |
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

### `qala get`

Fetches an active certificate by common name without knowing its serial. Writes `cert.pem` and `chain.pem` to `--out`. The `key.pem` file will be empty because private keys are not stored by the service after issuance — use `sign --reuse` if you need the key.

```sh
qala get server --cn <common-name> [--out <dir>]
qala get client --cn <common-name> [--out <dir>]
```

| Flag | Default | Description |
|---|---|---|
| `--cn` | (required) | Common name to look up |
| `--out` | `.` | Output directory for PEM files |

**Examples:**

```sh
# Fetch an existing server cert
qala get server --cn api.lab --out ./certs/api

# Fetch an existing client cert
qala get client --cn alice --out ./certs/alice
```

Exits with an error if no active certificate exists for the given CN and type.

---

### `qala list`

Lists issued certificates.

```sh
qala list [--type server|client] [--expired] [--quiet|-q]
```

| Flag | Description |
|---|---|
| `--type` | Filter by `server` or `client` |
| `--expired` | Include expired certificates (default: active only) |
| `--quiet`, `-q` | Output only serial numbers, one per line |

**Examples:**

```sh
# List all active certificates
qala list

# List only server certificates
qala list --type server

# List all client certificates including expired ones
qala list --type client --expired

# Output only serials (useful for scripting)
qala list --quiet
qala list --type server -q
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

Permanently removes a certificate record from the database by serial. The serial is shown in `qala list` output and is returned by all sign responses.

This does **not** revoke the certificate or update the CRL. To revoke and add to the CRL, use `qala revoke`.

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

After deletion the CN is free to be re-issued.

---

### `qala revoke`

Revokes a certificate, records the reason, and regenerates the CRL. The record is retained for audit purposes and CRL inclusion.

```sh
qala revoke <serial> [--reason <reason>]
```

| Flag | Default | Description |
|---|---|---|
| `--reason` | `unspecified` | RFC 5280 reason code (see below) |

Valid reason codes:

| Reason | Description |
|---|---|
| `unspecified` | No specific reason given (default) |
| `keyCompromise` | Private key was compromised |
| `affiliationChanged` | Subject's affiliation changed |
| `superseded` | Certificate has been superseded |
| `cessationOfOperation` | Subject has ceased operation |
| `certificateHold` | Certificate is on hold |

**Examples:**

```sh
# Revoke with default reason
qala revoke 3a2f1b...

# Revoke with a specific reason
qala revoke 3a2f1b... --reason keyCompromise
```

Prints confirmation with serial, revoked_at, and reason on success.

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

### `qala crl`

Fetches the current Certificate Revocation List from the server.

```sh
qala crl [--format der|pem] [--out <file>]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `pem` | Output format: `pem` or `der` |
| `--out` | stdout | Output file path |

**Examples:**

```sh
# Print CRL in PEM format to stdout
qala crl

# Save DER-format CRL to a file
qala crl --format der --out crl.der

# Save PEM-format CRL to a file
qala crl --out crl.pem
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
    "validity_days": 365
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `common_name` | string | yes | Certificate CN |
| `dns_names` | []string | no | DNS SANs |
| `ip_addresses` | []string | no | IP SANs |
| `key_algorithm` | string | no | `ecdsa` (default) or `rsa` |
| `validity_days` | int | no | 1–365, default 365 |

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

> **Note:** The private key is returned exactly once at issuance and is never returned by GET endpoints. Store it securely.

**Response `409 Conflict`** (CN already has an active certificate):

```json
{
  "error": "active certificate already exists for this common name",
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
    "validity_days": 365
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `common_name` | string | yes | Client identity |
| `key_algorithm` | string | no | `ecdsa` (default) or `rsa` |
| `validity_days` | int | no | 1–365, default 365 |

**Response `201 Created`:** Same shape as `POST /sign/server`.

**Response `409 Conflict`:** Same shape as `POST /sign/server` — includes `serial`.

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

# Include revoked
curl "http://localhost:8080/certs?revoked=true"

# Pagination
curl "http://localhost:8080/certs?limit=20&offset=40"
```

| Param | Description |
|---|---|
| `type` | `server` or `client` |
| `expired` | `true` to include expired (default: active only) |
| `revoked` | `true` to include revoked (default: excluded) |
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
      "expires_at": "2026-06-30T12:00:00Z",
      "revocation": null
    }
  ],
  "total": 1
}
```

The `revocation` field is `null` for active certificates. When a certificate has been revoked it contains:

```json
{
  "revocation": {
    "revoked_at": "2026-04-08T14:00:00Z",
    "reason": "keyCompromise"
  }
}
```

---

### `GET /certs/by-cn`

Returns the most recent active certificate matching a given common name and type. Both `type` and `cn` are required. The `private_key_pem` field is always empty because private keys are not returned by GET endpoints.

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

**Response `200 OK`:** Full certificate record (same shape as `GET /certs/{serial}`).

Returns `400` if `type` is missing or invalid. Returns `404` if no active certificate exists for the given CN and type.

---

### `GET /certs/{serial}`

Returns the full certificate record. The `private_key_pem` field is always empty because private keys are not returned after initial issuance.

```sh
curl http://localhost:8080/certs/3a2f1b...
```

**Response `200 OK`:**

```json
{
  "serial": "3a2f1b...",
  "type": "server",
  "common_name": "api.lab",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "issued_at": "2026-04-01T12:00:00Z",
  "expires_at": "2026-06-30T12:00:00Z",
  "revocation": null
}
```

---

### `DELETE /certs/{serial}`

Permanently removes a certificate record from the database. This does **not** revoke the certificate or update the CRL. To revoke and add to the CRL, use `POST /certs/{serial}/revoke`.

```sh
curl -s -X DELETE http://localhost:8080/certs/3a2f1b...
```

**Response `204 No Content`** on success. No body.

**Response `404 Not Found`** if the serial does not exist.

---

### `POST /certs/{serial}/revoke`

Marks a certificate as revoked, records the reason, and regenerates the CRL. The record is retained in the database for audit purposes and CRL inclusion.

```sh
curl -s -X POST http://localhost:8080/certs/3a2f1b.../revoke \
  -H 'Content-Type: application/json' \
  -d '{"reason": "keyCompromise"}'
```

**Request body (optional):**

| Field | Type | Required | Description |
|---|---|---|---|
| `reason` | string | no | RFC 5280 reason code. Default: `unspecified`. |

Valid reason codes: `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`.

**Response `200 OK`:**

```json
{
  "serial": "3a2f1b...",
  "revoked_at": "2026-04-08T14:00:00Z",
  "reason": "keyCompromise"
}
```

| Status | Condition |
|---|---|
| `400` | Unknown reason code |
| `404` | Serial not found |
| `409` | Certificate already revoked |

---

### `GET /crl`

Returns the current Certificate Revocation List signed by the Intermediate CA in DER format (`application/pkix-crl`). The CRL is valid for 24 hours and is regenerated on each revocation.

```sh
curl -o crl.der http://localhost:8080/crl
```

---

### `GET /crl.pem`

Returns the same CRL as `GET /crl` but PEM-encoded (`application/x-pem-file`).

```sh
curl http://localhost:8080/crl.pem
```

---

### Error responses

All errors return:

```json
{"error": "error-description"}
```

Conflict responses (`409`) from sign endpoints additionally include `"serial"`.

| Status | Description |
|---|---|
| `400` | Invalid request (missing fields, bad values, unknown reason code) |
| `404` | Certificate not found |
| `409` | Active certificate already exists for this CN (issuance), or certificate already revoked (revoke) |
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

Certificate defaults (`cert_org`, `default_validity_days`) are set once at `init` time via `--cert-org` and `--default-validity-days`, persisted to `config.json`, and read by `serve` on startup.

---

## File Layout

```
<data-dir>/                   Default: ./data
  root-ca.key.pem             Root CA private key  (keep offline after init)
  root-ca.cert.pem            Root CA certificate
  intermediate-ca.key.pem     Intermediate CA private key
  intermediate-ca.cert.pem    Intermediate CA certificate
  crl.pem                     Current CRL signed by the Intermediate CA
  config.json                 Operational config written by init, read by serve
  qala.db                     SQLite database (cert records)
```
