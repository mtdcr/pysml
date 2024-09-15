#!/usr/bin/env make -f

PYTHON = python

GITVER := $(shell git describe --exact-match --tags HEAD 2>/dev/null)

test:
	poetry run python3 -m unittest discover

dist/pysml-$(GITVER)-py3-none-any.whl:
	@[ -n "$(GITVER)" ] || (echo "Error: This commit doesn't have a tag."; false)
	@grep -q "^version = \"$(GITVER)\"$$" pyproject.toml || (echo "Error: Version in setup.py doesn't match '$(GITVER)'"; false)
	poetry build

dist: dist/pysml-$(GITVER)-py3-none-any.whl

upload: dist
	poetry publish

.PHONY: dist test upload
