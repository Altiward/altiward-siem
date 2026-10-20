.PHONY: help lint test check arm

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

lint: ## gofmt + go vet for the checker
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "run gofmt -w"; exit 1)
	go vet ./...

test: ## The checker's own tests (they also run the checks on this repository)
	go test -count=1 ./...

check: ## Check the rules, hunting queries, saved searches, fixtures and ARM template
	go run ./tools/rulecheck check

arm: ## Rebuild sentinel/azuredeploy.json from the rules
	scripts/build-arm.sh
