#!/bin/sh
# Rebuilds sentinel/azuredeploy.json, the ARM template behind the Deploy to Azure button,
# from sentinel/analytics-rules/*.yaml. CI fails when the committed file is out of date.
set -eu
cd "$(dirname "$0")/.."
go run ./tools/rulecheck arm . > sentinel/azuredeploy.json.tmp
mv sentinel/azuredeploy.json.tmp sentinel/azuredeploy.json
echo "wrote sentinel/azuredeploy.json"
