# MCP Security Scanner Makefile
# Simplifies common operations
DOCKER_DEFAULT_PLATFORM ?= linux/amd64

.PHONY: help build up down test scan example shell clean versions logs setup-clamav setup-yara setup-codeql setup-all test-examples test-real-repos test-mcp-only test-local-only

# Default target
help:
	@echo "🔐 MCP Security Scanner - Available Commands"
	@echo "================================================"
	@echo ""
	@echo "🚀 Development:"
	@echo "  make restart       - Stop, build, and start all services"
	@echo "  make build         - Build Docker images"
	@echo "  make up           - Start services"
	@echo "  make down         - Stop services"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test         - Run comprehensive tests (default)"
	@echo "  make test-examples - Test comprehensive vulnerability detection"
	@echo "  make test-mcp-only - Test MCP-specific vulnerabilities only"
	@echo "  make test-local-only - Test with local samples only"
	@echo "  make test-real-repos - Test with real vulnerable repositories"
	@echo "  make test-python  - Quick test with Python example"
	@echo "  make test-js      - Quick test with JavaScript example"
	@echo ""
	@echo "🔍 Scanning:"
	@echo "  make scan URL=<repo>  - Scan a repository"
	@echo "  make scan-vulnerable  - Scan local vulnerable examples"
	@echo ""
	@echo "🔧 Monitoring:"
	@echo "  make logs         - Show scanner logs"
	@echo "  make health       - Check scanner health"
	@echo "  make status       - Show service status"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean        - Clean up containers and volumes"
	@echo ""

# Build Docker image
build:
	DOCKER_DEFAULT_PLATFORM=$(DOCKER_DEFAULT_PLATFORM) docker-compose build

# Start scanner
up:
	DOCKER_DEFAULT_PLATFORM=$(DOCKER_DEFAULT_PLATFORM) docker-compose up -d
	@echo "Scanner running at http://localhost:8000"
	@echo "Health check: http://localhost:8000/health"

# Stop scanner
down:
	docker-compose down

restart: down build up
	@echo "✅ Scanner restarted successfully"

# Testing commands
test: test-examples
	@echo "🎉 All tests completed!"

test-examples:
	@echo "🧪 Testing with comprehensive vulnerability detection..."
	@echo "⚠️  Note: Scanner must be running (make up) before running tests"
	@echo "🔄 Waiting for scanner to be ready..."
	@timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || (echo "❌ Scanner not responding" && exit 1)
	@echo "✅ Scanner is ready, running tests..."
	@docker-compose run --rm scanner python3 tests/test_scanner.py --comprehensive

test-real-repos:
	@echo "🌐 Testing with real vulnerable repositories..."
	@timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || (echo "❌ Scanner not responding" && exit 1)
	@docker-compose run --rm scanner python3 tests/test_scanner.py --real-repos

test-mcp-only:
	@echo "🎯 Testing MCP-specific vulnerability detection..."
	@timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || (echo "❌ Scanner not responding" && exit 1)
	@docker-compose run --rm scanner python3 tests/test_scanner.py --mcp-only

test-local-only:
	@echo "🏠 Testing with local samples only..."
	@timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done' || (echo "❌ Scanner not responding" && exit 1)
	@docker-compose run --rm scanner python3 tests/test_scanner.py --local-only

test-python:
	@echo "🐍 Quick test with Python vulnerable server..."
	@mkdir -p /tmp/vuln-test-py
	@cp examples/vulnerable-mcp-server.py /tmp/vuln-test-py/
	@cd /tmp/vuln-test-py && git init > /dev/null 2>&1 && git config user.email "test@example.com" && git config user.name "Test" && git add . && git commit -m "test" > /dev/null 2>&1 || true
	@curl -s -X POST http://localhost:8000/scan \
		-H "Content-Type: application/json" \
		-d '{"repository_url": "file:///tmp/vuln-test-py"}' | python -m json.tool || cat
	@rm -rf /tmp/vuln-test-py

test-js:
	@echo "🟨 Quick test with JavaScript vulnerable server..."
	@mkdir -p /tmp/vuln-test-js
	@cp examples/test_vulnerable_mcp.js /tmp/vuln-test-js/
	@cd /tmp/vuln-test-js && git init > /dev/null 2>&1 && git config user.email "test@example.com" && git config user.name "Test" && git add . && git commit -m "test" > /dev/null 2>&1 || true
	@curl -s -X POST http://localhost:8000/scan \
		-H "Content-Type: application/json" \
		-d '{"repository_url": "file:///tmp/vuln-test-js"}' | python -m json.tool || cat
	@rm -rf /tmp/vuln-test-js

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
	docker compose logs -f scanner

# Additional monitoring commands
status:
	@echo "📊 Service Status:"
	@docker-compose ps

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

# Setup CodeQL
setup-codeql:
	./scripts/setup_codeql.sh

# Setup all security tools
setup-all: setup-clamav setup-yara setup-codeql
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