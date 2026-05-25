# SecretManager — Makefile
# Usage: make <target>
#
# All commands assume Docker Compose is running (make up)
# or you have a local .env and services accessible.

SHELL := /bin/bash
.PHONY: help up down build migrate rollback seed bootstrap test test-unit test-integration \
        lint format typecheck clean logs shell redis-cli generate-keys

# ── Colors ─────────────────────────────────────────────────────────────────────
CYAN  := \033[0;36m
RESET := \033[0m

help: ## Show this help
	@echo -e "$(CYAN)SecretManager$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2}'

# ── Docker ─────────────────────────────────────────────────────────────────────

up: ## Start all services
	docker compose up -d

up-dev: ## Start all services + pgAdmin
	docker compose --profile dev up -d

down: ## Stop all services
	docker compose down

build: ## Build Docker images
	docker compose build

rebuild: ## Rebuild images from scratch (no cache)
	docker compose build --no-cache

logs: ## Tail API logs
	docker compose logs -f api

logs-worker: ## Tail worker logs
	docker compose logs -f worker

# ── Database ───────────────────────────────────────────────────────────────────

migrate: ## Run Alembic migrations
	docker compose exec api alembic upgrade head

rollback: ## Rollback last migration
	docker compose exec api alembic downgrade -1

migrate-sql: ## Print SQL for next migration (offline mode)
	docker compose exec api alembic upgrade head --sql

new-migration: ## Create a new migration (usage: make new-migration NAME="add_x_column")
	docker compose exec api alembic revision --autogenerate -m "$(NAME)"

# ── Secrets bootstrapping ──────────────────────────────────────────────────────

generate-keys: ## Generate new JWT_SECRET_KEY, MASTER_ENCRYPTION_KEY, AUDIT_HMAC_KEY
	@echo "=== Generating secure keys ==="
	@echo -n "JWT_SECRET_KEY="; python3 -c "import secrets; print(secrets.token_hex(64))"
	@echo -n "MASTER_ENCRYPTION_KEY="; python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
	@echo -n "AUDIT_HMAC_KEY="; python3 -c "import secrets; print(secrets.token_hex(64))"
	@echo ""
	@echo "Copy these to your .env file."

bootstrap: ## Create the first super_admin (reads from .env)
	docker compose exec api python scripts/bootstrap.py

seed: ## Seed development data
	docker compose exec api python scripts/seed.py

# ── Testing ────────────────────────────────────────────────────────────────────

test: ## Run all tests with coverage
	docker compose exec api pytest -v --cov=app --cov-report=term-missing

test-unit: ## Run unit tests only (no DB/Redis required)
	docker compose exec api pytest tests/unit/ -v

test-integration: ## Run integration tests
	docker compose exec api pytest tests/integration/ -v

test-security: ## Run security/permission tests
	docker compose exec api pytest tests/security/ -v

test-local: ## Run tests locally (requires local .env and services)
	pytest -v --cov=app --cov-report=term-missing

# ── Code quality ───────────────────────────────────────────────────────────────

lint: ## Run ruff linter
	docker compose exec api ruff check app/ tests/ workers/

lint-fix: ## Run ruff with auto-fix
	docker compose exec api ruff check --fix app/ tests/ workers/

format: ## Run black formatter
	docker compose exec api black app/ tests/ workers/

format-check: ## Check formatting without changes
	docker compose exec api black --check app/ tests/ workers/

typecheck: ## Run mypy type checker
	docker compose exec api mypy app/

# ── Utilities ─────────────────────────────────────────────────────────────────

shell: ## Open shell in API container
	docker compose exec api /bin/bash

redis-cli: ## Open Redis CLI
	docker compose exec redis redis-cli

psql: ## Open PostgreSQL shell
	docker compose exec postgres psql -U smgr -d secretmanager

clean: ## Remove Docker volumes (DESTRUCTIVE — loses all data)
	@echo "WARNING: This will delete all database and Redis data."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker compose down -v

health: ## Check service health
	@curl -s http://localhost:8000/health | python3 -m json.tool

# ── Frontend ──────────────────────────────────────────────────────────────────

frontend-dev: ## Run frontend in dev mode (hot-reload)
	cd frontend && npm run dev

frontend-install: ## Install frontend dependencies
	cd frontend && npm ci

frontend-build: ## Build frontend production image
	docker compose build frontend

frontend-logs: ## Tail frontend logs
	docker compose logs -f frontend

# ── Development shortcuts ─────────────────────────────────────────────────────

dev: up migrate seed ## Quick start for development

reset: down clean up migrate seed ## Full reset with fresh data (DESTRUCTIVE)
