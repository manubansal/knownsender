.PHONY: setup test ci

setup:
	git config core.hooksPath .hooks
	chmod +x .hooks/*
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest --tb=short -q

# Run the full CI workflow locally via act (requires Docker + act).
# Reads secrets from .secrets — copy .secrets.example and fill in values first.
ci:
	act push -j test
