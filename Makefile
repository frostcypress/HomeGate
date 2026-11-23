.PHONY: check frontend

PYTHON ?= python3

check:
	$(PYTHON) scripts/project.py --check
	@set -eu; stage=$$(mktemp -d); trap 'rm -rf -- "$$stage"' EXIT; \
		$(PYTHON) scripts/production_runtime.py --package-output "$$stage" --bundled

frontend:
	$(PYTHON) scripts/build-js-views.py
