.PHONY: setup test ci dev dev-read-only

dev:
	@[ -f .env.local ] || (echo "Error: .env.local not found. Copy .env.local.example and fill in values."; exit 1)
	@set -a; . ./.env.local; set +a; \
	trap 'kill 0' EXIT; \
	uvicorn claven.server:app --port 8000 --reload & \
	NEXT_PUBLIC_API_URL=http://localhost:8000 npm --prefix web run dev & \
	wait

# Read-only view of the production database — safe to run alongside prod.
# Writes will fail at the DB level (SELECT-only role). Use this to observe
# dashboard state changes driven by live prod activity.
dev-read-only:
	@[ -f .env.local ] || (echo "Error: .env.local not found. Copy .env.local.example and fill in values."; exit 1)
	@set -a; . ./.env.local; set +a; \
	[ -n "$$DATABASE_URL_READONLY" ] || (echo "Error: DATABASE_URL_READONLY not set in .env.local."; exit 1); \
	trap 'kill 0' EXIT; \
	DATABASE_URL=$$DATABASE_URL_READONLY uvicorn claven.server:app --port 8000 --reload & \
	NEXT_PUBLIC_API_URL=http://localhost:8000 npm --prefix web run dev & \
	wait

setup:
	git config core.hooksPath .hooks
	chmod +x .hooks/*
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest --tb=short -q

# Run the full CI workflow locally via act (requires Docker + act).
# Reads secrets from .secrets -- copy .secrets.example and fill in values first.
# Post-job cleanup steps exit 127 in act (known bug: cache-save runs in the
# postgres service container which has no node). We check pytest output directly
# rather than relying on act's exit code to distinguish real failures.
ci:
	@act push -j test 2>&1 | tee /tmp/act-output.txt; \
	if grep -qE "[0-9]+ failed" /tmp/act-output.txt; then \
		echo ""; echo "FAIL: tests failed"; exit 1; \
	elif grep -qE "[0-9]+ passed" /tmp/act-output.txt; then \
		echo ""; echo "OK: tests passed"; exit 0; \
	else \
		echo ""; echo "FAIL: no test results found"; exit 1; \
	fi
