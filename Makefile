.PHONY: setup test ci

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
