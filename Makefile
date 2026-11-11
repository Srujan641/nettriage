# NetTriage: common tasks. Run `make` to list them.
.DEFAULT_GOAL := help
PY := backend/.venv/bin

help:           ## list the available tasks
	@grep -E '^[a-z-]+: .*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

setup:          ## install backend (virtualenv) and frontend dependencies
	cd backend && python3 -m venv .venv && ./.venv/bin/pip install -q -e ".[api,dev]"
	cd frontend && npm install --silent

dev:            ## run the API and the dashboard together (http://localhost:5173)
	./scripts/dev.sh

api:            ## run only the API (http://127.0.0.1:8000)
	$(PY)/nettriage serve

web:            ## run only the dashboard dev server
	cd frontend && npm run dev

test:           ## run every backend test, including the live-internet ones
	cd backend && ./.venv/bin/pytest -q

test-offline:   ## run the tests that need no internet
	cd backend && ./.venv/bin/pytest -q -m "not network"

bench:          ## score the tool against targets with known faults (writes docs/METRICS.md)
	$(PY)/python scripts/benchmark.py

coverage:       ## run the tests with a line-coverage report
	cd backend && ./.venv/bin/pytest -q --cov=nettriage --cov-report=term

lint:           ## lint the backend and type-check the frontend
	cd backend && ./.venv/bin/ruff check nettriage tests
	cd frontend && npm run typecheck

lab-up:         ## build and start the Docker lab
	./labs/run.sh up

lab-run:        ## run all five lab scenarios and record their captures
	./labs/run.sh all

lab-down:       ## stop the lab
	./labs/run.sh down

.PHONY: help setup dev api web test test-offline bench coverage lint lab-up lab-run lab-down
