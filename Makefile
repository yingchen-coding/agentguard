.PHONY: install test lint typecheck build check-dist selfscan bench adversarial contracts workflow-audit corpus quality all

PYTHON ?= python3

install:        ## install in editable mode with dev deps
	$(PYTHON) -m pip install -e ".[dev]"

test:           ## run the test suite
	$(PYTHON) -m pytest -q

bench:          ## run the security accuracy benchmark (recall + precision)
	$(PYTHON) eval/benchmark.py --verbose

lint:           ## ruff lint
	$(PYTHON) -m ruff check .

typecheck:      ## strict static type checking
	$(PYTHON) -m mypy agentguard

build:          ## build sdist + wheel
	$(PYTHON) -m build

check-dist: build  ## validate package metadata and rendered README
	$(PYTHON) -m twine check dist/*

selfscan:       ## dogfood: lint examples + supply-chain self-scan
	$(PYTHON) -m agentguard examples || true
	$(PYTHON) -m agentguard . --publish-check \
		--select AL503,AL510,AL511,AL512,AL513 --fail-at major

adversarial:    ## metamorphic prompt-structure review
	$(PYTHON) eval/adversarial_review.py

contracts:      ## code/docs/evidence/skill drift gate
	$(PYTHON) tools/verify_contracts.py

workflow-audit: ## bound matrix expansion, duplicate expensive work, and missing timeouts
	$(PYTHON) tools/workflow_audit.py

corpus:         ## parallel real-repository calibration loop
	$(PYTHON) tools/corpus_audit.py \
		--manifest docs/corpus/manifest.json --output build/corpus-audit

quality: lint typecheck test bench adversarial contracts workflow-audit check-dist selfscan

all: quality
