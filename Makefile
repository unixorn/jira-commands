h: help

help:
	@echo "Options:"
	@echo "format: Reformat all python files with black"
	@echo "tests: Run tests with nosetest"
	@echo "verbose_tests: Run tests with nosetest -v"

f: format
t: test
i: image
image: local

format: format_code format_tests

format_code:
	black jira_commands/*.py jira_commands/cli/*.py

format_tests:
	black tests/*.py

tests: test
test:
	nosetests

verbose_tests: verbose_test
verbose_test:
	nosetests -v

wheel: clean format requirements.txt
	poetry build

local: wheel
	docker buildx build --load -t unixorn/jira-commands .

fatimage: wheel
	docker buildx build --platform linux/arm64,linux/amd64 --push -t unixorn/jira-commands .
	make local

clean:
	rm -f dist/*

fat:
	make fatimage

requirements.txt: poetry.lock Makefile
	poetry export -o requirements.txt --without-hashes
