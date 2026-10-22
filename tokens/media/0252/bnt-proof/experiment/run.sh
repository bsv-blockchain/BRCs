#!/bin/sh
# The E2E token experiment: checks each claim of the BNT paper on the test
# token's mainnet transactions. --refresh pulls the evidence from WhatsOnChain
# again; otherwise it runs offline on experiment/mainnet.json.
set -e
cd "$(dirname "$0")/.."
[ -d experiment/node_modules/@bsv/sdk ] || npm ci --prefix experiment --min-release-age=7 --no-audit --no-fund
if [ "$1" = "--refresh" ] || [ ! -f experiment/mainnet.json ]; then node experiment/fetch.mjs; fi
(cd experiment && node --test chain.test.mjs)
cargo test -p bnt-step --test mainnet_e2e
