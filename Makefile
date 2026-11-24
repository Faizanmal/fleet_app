.PHONY: setup up migrate ingest seed test lint eval-offline eval-security eval-live action-demo api-types check down verify-audit replay-run demo-up demo-down demo-reset

setup:
	python scripts/tasks.py setup
up:
	python scripts/tasks.py up
migrate:
	python scripts/tasks.py migrate
ingest:
	python scripts/tasks.py ingest
seed:
	python scripts/tasks.py seed
test:
	python scripts/tasks.py test
lint:
	python scripts/tasks.py lint
eval-offline:
	python scripts/tasks.py eval-offline
eval-security:
	python scripts/tasks.py eval-security
verify-audit:
	python scripts/verify_audit_chain.py
replay-run:
	python scripts/replay_run.py $(RUN_ID)
demo-up:
	python scripts/tasks.py demo-up
demo-down:
	python scripts/tasks.py demo-down
demo-reset:
	python scripts/tasks.py demo-reset
action-demo:
	python scripts/tasks.py action-demo
api-types:
	python scripts/tasks.py api-types
check:
	python scripts/tasks.py check
down:
	python scripts/tasks.py down
