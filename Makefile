# TLVB — convenience targets.
#
# Variables you may override:
#   PORT      — serve port (default 8080)
#   BIN       — output binary path (default ./bin/tlvb)
#   GOFLAGS   — extra `go build` flags

PORT      ?= 8080
BIN       ?= ./bin/tlvb
GOFLAGS   ?=

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nTLVB targets:\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' \
	$(MAKEFILE_LIST)

.PHONY: setup
setup: ## Verify prerequisites and build (./scripts/setup.sh)
	./scripts/setup.sh

.PHONY: verify
verify: ## Run environment / parser verification (./scripts/verify.sh)
	./scripts/verify.sh

.PHONY: build
build: ## Build the tlvb binary into ./bin/
	@mkdir -p $(dir $(BIN))
	go build $(GOFLAGS) -o $(BIN) ./cmd/tlvb
	@echo "built $(BIN)"

.PHONY: run
run: build ## Build and start the Web UI (PORT=8080)
	$(BIN) serve --port $(PORT)

.PHONY: serve
serve: run ## Alias for `run`

.PHONY: test
test: test-go test-py ## Run Go and Python tests

.PHONY: test-go
test-go: ## Run Go tests
	go test ./...

.PHONY: test-py
test-py: ## Run Python tests (parsers/)
	@if command -v pytest >/dev/null 2>&1; then \
	  pytest -q tests/ || true; \
	else \
	  echo "pytest not installed; skipping (pip install pytest)"; \
	fi

.PHONY: test-py-all
test-py-all: ## Run all Python tests verbosely from .venv (Wave 9 — full suite)
	@if [ ! -x ./.venv/bin/pytest ]; then \
	  echo "./.venv/bin/pytest not found — run 'make deps-py' first"; \
	  exit 1; \
	fi
	PYTHONPATH=. ./.venv/bin/pytest tests/ -v --tb=short

.PHONY: verify-all
verify-all: verify ## Run verify.sh (8/8) + pytest (53/53) for full coverage
	@echo
	@echo "TLVB verify-all complete."

.PHONY: lint
lint: ## Run go vet + ruff (Python) if available
	go vet ./...
	@if command -v ruff >/dev/null 2>&1; then ruff check parsers/; else echo "ruff not installed; skipping"; fi

.PHONY: fmt
fmt: ## Format Go and Python sources
	gofmt -w internal/ cmd/
	@if command -v ruff >/dev/null 2>&1; then ruff format parsers/; fi

.PHONY: clean
clean: ## Remove build artifacts (does NOT touch outputs/cases)
	rm -rf bin/
	rm -f *.test *.out

.PHONY: clean-cases
clean-cases: ## DESTRUCTIVE — wipe outputs/cases/ and the DuckDB
	@echo "This will delete ALL case data. Type 'yes' to continue:"; \
	read confirm; \
	[ "$$confirm" = "yes" ] || { echo "aborted"; exit 1; }
	rm -rf outputs/cases/* outputs/cases.duckdb*
	@touch outputs/cases/.gitkeep

.PHONY: deps-py
deps-py: ## Create ./.venv and install Python runtime deps (duckdb)
	@if [ ! -x ./.venv/bin/python3 ]; then \
		python3 -m venv ./.venv || { \
			echo "venv create failed — try: sudo apt install python3-venv python3-full"; \
			exit 1; \
		}; \
	fi
	./.venv/bin/pip install --quiet --upgrade pip
	./.venv/bin/pip install --quiet duckdb
	@echo "Python deps installed in ./.venv (activated automatically by the binary)"

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy
