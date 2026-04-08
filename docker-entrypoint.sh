#!/bin/sh
set -e

DATA_DIR="${QALA_DATA_DIR:-/data}"

if [ ! -f "${DATA_DIR}/intermediate-ca.cert.pem" ]; then
    echo "No CA found in ${DATA_DIR}, running init..."
    qala init --data-dir "${DATA_DIR}"
fi

exec qala serve --data-dir "${DATA_DIR}" "$@"
