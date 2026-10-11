.PHONY: check frontend reference-check draft

check:
	python3 scripts/project.py --check
	python3 scripts/重构回归.py
	python3 scripts/导航安全回归.py
	python3 scripts/frontend-source-regressions.py

frontend:
	python3 scripts/sync-frontend.py
	python3 scripts/build-js-views.py

reference-check:
	cd project/core/src && go test -mod=vendor ./... && go vet -mod=vendor ./...

draft:
	python3 scripts/生成接续包.py --target pending --stage 规范迁移 --draft
