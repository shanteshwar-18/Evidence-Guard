.PHONY: up down logs test lint seed help

# ── Evidence Guard Makefile ───────────────────────────────────────────────────
# make up    – start all services (backend, postgres, minio)
# make down  – stop and remove containers
# make logs  – tail all logs
# make test  – run backend and e2e tests
# make lint  – lint backend (ruff) and frontend (eslint)
# make seed  – seed database with synthetic data

COMPOSE       = docker compose -f infra/docker-compose.yml
BACKEND_SVC   = backend

help:
	@echo ""
	@echo "  Evidence Guard – available targets"
	@echo "  ────────────────────────────────────"
	@echo "  make up    start all services"
	@echo "  make down  stop all services"
	@echo "  make logs  tail all logs"
	@echo "  make test  run all tests"
	@echo "  make lint  lint all code"
	@echo "  make seed  seed synthetic data"
	@echo ""

up:
	@echo "Starting Evidence Guard services..."
	$(COMPOSE) up -d --build
	@echo "Waiting for health checks..."
	@sleep 5
	$(COMPOSE) ps

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

test:
	@echo "Running backend tests..."
	$(COMPOSE) exec -T $(BACKEND_SVC) pytest backend/tests/ -v --tb=short
	@echo "Running e2e tests..."
	cd tests/e2e && npm ci --quiet && npx playwright test

lint:
	@echo "Linting backend..."
	$(COMPOSE) exec -T $(BACKEND_SVC) ruff check backend/
	@echo "Linting frontend..."
	cd frontend && npm run lint

seed:
	@echo "Seeding synthetic data..."
	$(COMPOSE) exec -T $(BACKEND_SVC) python scripts/seed.py

# ── Fabric network (separate from docker-compose) ────────────────────────────
fabric-up:
	cd blockchain/network && bash start-fabric.sh

fabric-down:
	cd blockchain/network && bash stop-fabric.sh

# ── Ethereum fallback (break-glass Scenario 1) ───────────────────────────────
eth-up:
	cd blockchain/network && bash start-eth.sh

eth-down:
	cd blockchain/network && bash stop-eth.sh
