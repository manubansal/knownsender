.PHONY: setup test

setup:
	git config core.hooksPath .hooks
	chmod +x .hooks/*
	pip install -r requirements.txt -r requirements-dev.txt

test:
	pytest --tb=short -q
