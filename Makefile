.PHONY: install test lint typecheck build selfscan all

install:        ## install in editable mode with dev deps
	pip install -e ".[dev]"

test:           ## run the test suite
	pytest -q

lint:           ## ruff lint
	ruff check .

build:          ## build sdist + wheel
	python -m build

selfscan:       ## dogfood: lint examples + supply-chain self-scan
	agent-lint examples || true
	agent-lint . --publish-check --select AL503,AL510,AL511,AL512,AL513 --fail-at major

all: lint test  ## lint + test
