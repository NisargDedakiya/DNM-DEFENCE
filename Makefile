# Track 1 Security Platform — operator commands.
# Run `make help` for the list. The common flow on a fresh server is:
#   make setup        (once — writes backend/.env with secure secrets)
#   make up           (build + start the whole stack)
#   make create-admin (once — your first login)
#   make health       (confirm everything is actually running)

.DEFAULT_GOAL := help
COMPOSE := docker compose

.PHONY: help setup up down restart rebuild logs ps health create-admin \
        migrate shell-api backup restore test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## First-run: generate backend/.env with secure random secrets
	python3 scripts/generate_env.py
	@echo ""
	@echo "Next: 'make up', then 'make create-admin', then open http://localhost"

up: ## Build and start the whole stack in the background
	$(COMPOSE) up -d --build
	@echo ""
	@echo "Stack starting. Run 'make health' in ~30s, then open http://localhost"

down: ## Stop and remove all containers (data volume is kept)
	$(COMPOSE) down

restart: ## Restart every service (picks up .env changes)
	$(COMPOSE) restart

rebuild: ## Rebuild images and restart (after a code/dependency change)
	$(COMPOSE) up -d --build

logs: ## Tail logs from all services (Ctrl-C to stop)
	$(COMPOSE) logs -f --tail=100

ps: ## Show the status of every service
	$(COMPOSE) ps

health: ## Check API health + the in-app diagnostics (worker/redis/tools)
	@echo "--- API liveness ---"
	@curl -fsS http://localhost/health && echo "" || echo "API not reachable yet"
	@echo "--- container status ---"
	@$(COMPOSE) ps

create-admin: ## Create your first admin login (prompts for email/password)
	@read -p "Admin email: " email; \
	$(COMPOSE) run --rm api python -m app.scripts.create_admin $$email

migrate: ## Apply database migrations (also runs automatically on `up`)
	$(COMPOSE) run --rm api alembic upgrade head

shell-api: ## Open a shell inside the API container
	$(COMPOSE) exec api sh

backup: ## Back up the database to ./backups/track1_<timestamp>.sql.gz
	@mkdir -p backups
	@ts=$$(date +%Y%m%d_%H%M%S); \
	$(COMPOSE) exec -T db pg_dump -U track1 track1 | gzip > backups/track1_$$ts.sql.gz && \
	echo "Wrote backups/track1_$$ts.sql.gz"

restore: ## Restore the database from a dump (make restore BACKUP=backups/track1_x.sql.gz)
	@test -n "$(BACKUP)" || (echo "Usage: make restore BACKUP=backups/track1_<ts>.sql.gz" && exit 1)
	gunzip -c $(BACKUP) | $(COMPOSE) exec -T db psql -U track1 track1

test: ## Run the backend test suite inside the API image
	$(COMPOSE) run --rm api pytest -q
