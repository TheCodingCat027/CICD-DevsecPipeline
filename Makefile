.PHONY: setup validate test pipeline-local pipeline-local-fail lint clean

PYTHON := python3
VENV := .venv

ifeq ($(OS),Windows_NT)
    PYTHON := python
    VENV_BIN := $(VENV)/Scripts
else
    VENV_BIN := $(VENV)/bin
endif

PIP := $(VENV_BIN)/pip
PYTEST := $(VENV_BIN)/pytest

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r contracts/requirements.txt
	$(PIP) install -r demo-app/fixed/requirements.txt
	@echo "Setup complete."

validate:
	$(PYTHON) contracts/validate.py contracts/samples
	$(PYTHON) contracts/validate.py --policy security-policy.yaml
	@echo "All samples and policy validated successfully."

test:
	$(PYTEST) contracts/tests/ demo-app/ -v
	@echo "--- Running stage stub tests ---"
	@for stage in secrets sast sca iac container sbom; do \
		echo "Testing stage: $$stage"; \
		bash stages/$$stage/tests/run_test.sh || exit 1; \
	done
	@echo "All tests passed."

pipeline-local:
	bash scripts/run-local-pipeline.sh demo-app/vulnerable

pipeline-local-fail:
	GATE_FORCE_FAIL=1 bash scripts/run-local-pipeline.sh demo-app/vulnerable

lint:
	@echo "--- Linting shell scripts ---"
	@if command -v shellcheck >/dev/null 2>&1; then \
		find stages scripts -name "*.sh" -exec shellcheck {} \; && echo "shellcheck passed"; \
	else \
		echo "shellcheck not available, skipping"; \
	fi
	@echo "--- Compiling Python ---"
	$(PYTHON) -m compileall contracts/ gate/ demo-app/ -q && echo "Python compile check passed"
	@echo "--- Checking workflow ---"
	@if command -v actionlint >/dev/null 2>&1; then \
		actionlint .github/workflows/pipeline.yml && echo "actionlint passed"; \
	else \
		echo "actionlint not available, skipping"; \
	fi

clean:
	rm -rf $(VENV) reports/ out/ gate-out/ .pytest_cache/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."