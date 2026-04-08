#!/bin/sh
set -e

DATA_DIR="${SEACRT_DATA_DIR:-/data}"

if [ ! -f "${DATA_DIR}/intermediate-ca.cert.pem" ]; then
    echo "No CA found in ${DATA_DIR}, running init..."
    seacrt init --data-dir "${DATA_DIR}"
fi

exec seacrt serve --data-dir "${DATA_DIR}" "$@"
