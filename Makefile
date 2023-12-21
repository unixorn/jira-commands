h: help

.PHONY: all clean format help image test tests f h i t

help:
	@echo "Options:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

f: format
t: test
i: image
image: local ## Make a docker image that only supports the architecture we're running on for quick testing

MODULE_VERSION=$(shell poetry run python3 -c 'from jira_commands import __version__;print(__version__)' )

format: format_code format_tests ## Reformat our .py files with black

format_code:
	black .

format_tests:
	black tests/*.py

tests: test ## Run nose tests
test:
	nosetests

verbose_tests: verbose_test ## Run nose tests with verbose enabled
verbose_test:
	nosetests -v

wheel: clean format requirements.txt ## Make a wheel file
	poetry build

local: wheel requirements.txt
	docker build --load -t ${USER}/jira-commands --build-arg application_version=${MODULE_VERSION} -f Dockerfile.testing --progress plain .

multiimage: wheel ## Make a multi-architecture docker image
	docker buildx build --platform linux/arm64,linux/amd64 --push -t unixorn/jira-commands:${MODULE_VERSION} --build-arg application_version=${MODULE_VERSION} .
	make local

clean: ## Clean up our checkout
	rm -fv dist/*
	hooks/scripts/clean-up-pyc-and-pyo-files

multi:
	make multiimage

requirements.txt: poetry.lock Makefile
	poetry export -o requirements.txt --without-hashes
