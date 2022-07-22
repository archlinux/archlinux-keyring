PREFIX ?= /usr/local
KEYRING_TARGET_DIR=$(DESTDIR)$(PREFIX)/share/pacman/keyrings/
KEYRING_FILES=$(wildcard build/*.gpg) $(wildcard build/*-revoked) $(wildcard build/*-trusted)
SCRIPT_TARGET_DIR=$(DESTDIR)$(PREFIX)/bin/
SCRIPT_FILES=wkd_sync/archlinux-keyring-wkd-sync
SYSTEMD_SYSTEM_UNIT_DIR=$(DESTDIR)$(shell pkgconf --variable systemd_system_unit_dir systemd)
SYSTEMD_FILES=$(wildcard wkd_sync/*.service) $(wildcard wkd_sync/*.timer)
SYSTEMD_TIMER_DIR=$(SYSTEMD_SYSTEM_UNIT_DIR)/timers.target.wants/
SYSTEMD_TIMER_FILE=archlinux-keyring-wkd-sync.timer
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
	install -vDm 755 $(SCRIPT_FILES) -t $(SCRIPT_TARGET_DIR)
	install -vDm 644 $(SYSTEMD_FILES) -t $(SYSTEMD_SYSTEM_UNIT_DIR)
	install -vdm 755 $(SYSTEMD_TIMER_DIR)
	ln -sv ../$(SYSTEMD_TIMER_FILE) $(SYSTEMD_TIMER_DIR)/$(SYSTEMD_TIMER_FILE)

uninstall:
	rm -f $(KEYRING_TARGET_DIR)/archlinux{.gpg,-trusted,-revoked}
	rmdir -p --ignore-fail-on-non-empty $(KEYRING_TARGET_DIR)

.PHONY: all lint fmt check test clean install uninstall
