#!/usr/bin/env make -f

PYTHON = python

GITVER := $(shell git describe --exact-match --tags HEAD 2>/dev/null)

check:
	@[ -n "$(GITVER)" ] || (echo "Error: This commit doesn't have a tag."; false)
	@grep -q "^version = \"$(GITVER)\"$$" pyproject.toml || (echo "Error: Version in setup.py doesn't match '$(GITVER)'"; false)

dist: check
	poetry build

upload: check
	poetry publish
