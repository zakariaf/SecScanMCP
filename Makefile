# MCP Security Scanner Makefile
# Simplifies common operations

.PHONY: help build up down test scan example shell clean versions logs

# Default target
help:
	@echo "MCP Security Scanner - Available commands:"
	@echo ""
	@echo "  make build       - Build Docker image"
	@echo "  make up          - Start scanner service"
	@echo "  make down        - Stop scanner service"
	@echo "  make test        - Run tests"
	@echo "  make scan URL=<repo>  - Scan a repository"
	@echo "  make example     - Run example scan"
	@echo "  make shell       - Open development shell"
	@echo "  make clean       - Remove containers and volumes"
	@echo "  make versions    - Show tool versions"
	@echo "  make logs        - Show scanner logs"
	@echo ""
	@echo "Development:"
	@echo "  make dev         - Start with hot reload"
	@echo "  make install-local - Install tools locally"
	@echo "  make setup-ClamAV  - Setup ClamAV for local development"
	@echo "  make setup-yara  - Setup YARA for local development"
	@echo "  make setup-all   - Setup all security tools"

# Build Docker image
build:
	docker-compose build

# Start scanner
up:
	docker-compose up -d
	@echo "Scanner running at http://localhost:8000"
	@echo "Health check: http://localhost:8000/health"

# Stop scanner
down:
	docker-compose down

# Run tests
test:
	docker-compose run --rm test-runner

# Scan a repository (usage: make scan URL=https://github.com/user/repo)
scan:
	@if [ -z "$(URL)" ]; then \
		echo "Error: Please provide URL"; \
		echo "Usage: make scan URL=https://github.com/user/repo"; \
		exit 1; \
	fi
	@echo "Scanning $(URL)..."
	@curl -s -X POST http://localhost:8000/scan \
		-H "Content-Type: application/json" \
		-d '{"repository_url": "$(URL)"}' | (command -v python3 >/dev/null 2>&1 && python3 -m json.tool) || (command -v python >/dev/null 2>&1 && python -m json.tool) || cat

# Run example scan
example:
	docker-compose run --rm scanner python examples/scan_example.py https://github.com/user/test-repo

# Open development shell
shell:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm dev-shell

# Clean everything
clean:
	docker-compose down -v
	rm -f security_report_*.json
	@echo "Cleaned up containers and volumes"

# Show tool versions
versions:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm tool-versions

# Show logs
logs:
	docker-compose logs -f scanner

# Development mode with hot reload
dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Install tools locally (for development)
install-local:
	./scripts/install-tools.sh

# Setup ClamAV
setup-clamav:
	./scripts/setup_clamav.sh

# Setup YARA
setup-yara:
	./scripts/setup_yara.sh

# Setup all security tools
setup-all: setup-clamav setup-yara
	@echo "All security tools installed!"

# Quick health check
health:
	@curl -s http://localhost:8000/health | (command -v python3 >/dev/null 2>&1 && python3 -m json.tool) || (command -v python >/dev/null 2>&1 && python -m json.tool) || (echo "JSON formatting not available, raw response:" && cat) || echo "Scanner not running"

# Scan vulnerable example
scan-vulnerable:
	@echo "Creating vulnerable test project..."
	@mkdir -p /tmp/vuln-test
	@cp examples/vulnerable-mcp-server.py /tmp/vuln-test/
	@cd /tmp/vuln-test && git init && git add . && git commit -m "test" > /dev/null 2>&1 || true
	@echo "Scanning vulnerable project..."
	@curl -s -X POST http://localhost:8000/scan \
		-H "Content-Type: application/json" \
		-d '{"repository_url": "file:///tmp/vuln-test"}' | (command -v python3 >/dev/null 2>&1 && python3 -m json.tool) || (command -v python >/dev/null 2>&1 && python -m json.tool) || cat
	@rm -rf /tmp/vuln-test