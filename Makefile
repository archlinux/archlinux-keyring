PREFIX ?= /usr/local
KEYRING_TARGET_DIR=$(DESTDIR)$(PREFIX)/share/pacman/keyrings/
KEYRING_FILES=$(wildcard build/*.gpg) $(wildcard build/*-revoked) $(wildcard build/*-trusted)
SOURCES := $(shell find keyring) $(shell find libkeyringctl -name '*.py' -or -type d) keyringctl

all: build

lint:
	black --check --diff keyringctl libkeyringctl tests
	isort --diff .
	flake8 keyringctl libkeyringctl tests
	mypy --install-types --non-interactive keyringctl libkeyringctl tests

fmt:
	black .
	isort .

check:
	./keyringctl -v check

test:
	coverage run
	coverage xml
	coverage report --fail-under=100.0

build: $(SOURCES)
	./keyringctl -v build

clean:
	rm -rf build

install: build
	install -vDm 755 $(KEYRING_FILES) -t $(KEYRING_TARGET_DIR)

uninstall:
	rm -f $(KEYRING_TARGET_DIR)/archlinux{.gpg,-trusted,-revoked}
	rmdir -p --ignore-fail-on-non-empty $(KEYRING_TARGET_DIR)

.PHONY: all lint fmt check test clean install uninstall
