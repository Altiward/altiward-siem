#!/bin/sh
# Copies the OCSF records the checks use from the projects that produce them:
#   scripts/sync-fixtures.sh <altiward checkout> <altiward-forwarder checkout>
# Run it when either project changes its records, then go run ./tools/rulecheck check.
set -eu
if [ $# -ne 2 ]; then
  echo "usage: $0 <altiward checkout> <altiward-forwarder checkout>" >&2
  exit 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
copy() { # copy <source folder> <fixtures folder>
  [ -d "$1" ] || { echo "$1: not found" >&2; exit 1; }
  rm -f "$here/fixtures/$2"/*.json
  mkdir -p "$here/fixtures/$2"
  cp "$1"/*.json "$here/fixtures/$2/"
}
copy "$1/integrations/ocsf-examples" altiward
copy "$2/testdata/ocsf" forwarder
echo "fixtures updated from $1 and $2"
