PREFIX ?= /usr/local
KEYRING_TARGET_DIR=$(DESTDIR)$(PREFIX)/share/pacman/keyrings/
KEYRING_FILES=$(wildcard keyring/output/*.gpg) $(wildcard keyring/output/*-revoked) $(wildcard keyring/output/*-trusted)

all: build

lint:
	black --check --diff keyringctl
	isort --diff .
	flake8 keyringctl
	mypy --install-types --non-interactive keyringctl

build:
	./keyringctl -v export-keyring

install:
	install -vDm 755 $(KEYRING_FILES) -t $(KEYRING_TARGET_DIR)

uninstall:
	rm -f $(KEYRING_TARGET_DIR)/archlinux{.gpg,-trusted,-revoked}
	rmdir -p --ignore-fail-on-non-empty $(KEYRING_TARGET_DIR)

.PHONY: build install lint uninstall
