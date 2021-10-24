PREFIX ?= /usr/local
KEYRING_TARGET_DIR=$(DESTDIR)$(PREFIX)/share/pacman/keyrings/
KEYRING_FILES=$(wildcard build/*.gpg) $(wildcard build/*-revoked) $(wildcard build/*-trusted)

all: build

lint:
	black --check --diff keyringctl libkeyringctl
	isort --diff .
	flake8 keyringctl libkeyringctl
	mypy --install-types --non-interactive keyringctl libkeyringctl

fmt:
	black .
	isort .

build:
	./keyringctl -v build

install:
	install -vDm 755 $(KEYRING_FILES) -t $(KEYRING_TARGET_DIR)

uninstall:
	rm -f $(KEYRING_TARGET_DIR)/archlinux{.gpg,-trusted,-revoked}
	rmdir -p --ignore-fail-on-non-empty $(KEYRING_TARGET_DIR)

.PHONY: build install lint uninstall
