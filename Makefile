.PHONY: check frontend draft

PYTHON ?= python3

check:
	$(PYTHON) scripts/project.py --check
	$(PYTHON) scripts/native-target-audit-regressions.py
	$(PYTHON) scripts/重构回归.py
	$(PYTHON) scripts/导航安全回归.py
	$(PYTHON) scripts/frontend-source-regressions.py

frontend:
	$(PYTHON) scripts/build-js-views.py

draft:
	$(PYTHON) scripts/生成接续包.py --target pending --stage 规范迁移 --draft
