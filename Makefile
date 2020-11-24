#!/usr/bin/env make -f

PYTHON = python

GITVER := $(shell git describe --exact-match --tags HEAD 2>/dev/null)

dist: check
	$(PYTHON) setup.py sdist bdist_wheel

check:
	@$(PYTHON) -c "import setuptools_git" 2>/dev/null || (echo "Error: Missing build requirement: setuptools-git"; false)
	@[ -n "$(GITVER)" ] || (echo "Error: This commit doesn't have a tag."; false)
	@grep -q "^\s\+version='$(GITVER)',$$" setup.py || (echo "Error: Version in setup.py doesn't match '$(GITVER)'"; false)
