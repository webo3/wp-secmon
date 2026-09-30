# Development tasks. Run `make help` for the list.

PHP ?= php
DOCKER ?= docker

.PHONY: build test e2e e2e-debian e2e-el8 clean help

build: ## Build dist/wp-secmon.phar and dist/wp-secmon.phar.sha256
	$(PHP) -d phar.readonly=0 build.php

test: ## Unit tests: parsing, diffs, version matching, file scan, alerts, translations
	$(PHP) tests/unit.php

e2e: e2e-debian e2e-el8 ## Both end-to-end tests (Docker, needs network access)

e2e-debian: ## End-to-end test on Debian 12, PHP 8.2
	$(DOCKER) build -t wp-secmon-test -f tests/integration/Dockerfile .
	$(DOCKER) run --rm wp-secmon-test

e2e-el8: ## End-to-end test on AlmaLinux 8, PHP 7.4, without the posix extension
	$(DOCKER) build -t wp-secmon-test-el8 -f tests/integration/Dockerfile.el8 .
	$(DOCKER) run --rm wp-secmon-test-el8

clean: ## Remove dist/
	rm -rf dist

help: ## List the targets
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{ printf "  %-11s %s\n", $$1, $$2 }'
