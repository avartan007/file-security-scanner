.PHONY: install dev lint test clean help

help:
	@echo "File Security Scanner - Development Commands"
	@echo ""
	@echo "make install     Install dependencies"
	@echo "make dev         Install with dev dependencies"
	@echo "make lint        Run code quality checks"
	@echo "make test        Run unit tests"
	@echo "make clean       Remove cache files"
	@echo "make run         Run the scanner"
	@echo ""

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements.txt -r requirements-dev.txt

lint:
	flake8 src/ tests/
	black --check src/ tests/
	isort --check-only src/ tests/

test:
	python -m pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage

run:
	python run.py
