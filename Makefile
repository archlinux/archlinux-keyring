PREFIX ?= /usr/local
KEYRING_TARGET_DIR=$(DESTDIR)$(PREFIX)/share/pacman/keyrings/
KEYRING_FILES=$(wildcard build/*.gpg) $(wildcard build/*-revoked) $(wildcard build/*-trusted)

all: build

lint:
	black --check --diff keyringctl libkeyringctl tests
	isort --diff .
	flake8 keyringctl libkeyringctl tests
	mypy --install-types --non-interactive keyringctl libkeyringctl tests

fmt:
	black .
	isort .

test:
	coverage run
	coverage report
	coverage xml -o build/coverage.xml

build:
	./keyringctl -v build

install:
	install -vDm 755 $(KEYRING_FILES) -t $(KEYRING_TARGET_DIR)

uninstall:
	rm -f $(KEYRING_TARGET_DIR)/archlinux{.gpg,-trusted,-revoked}
	rmdir -p --ignore-fail-on-non-empty $(KEYRING_TARGET_DIR)

.PHONY: all lint fmt test build install uninstall
