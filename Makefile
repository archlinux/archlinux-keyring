PREFIX ?= /usr/local
BUILD_DIR ?= build
KEYRING_TARGET_DIR ?= $(PREFIX)/share/pacman/keyrings/
SCRIPT_TARGET_DIR ?= $(PREFIX)/bin/
SYSTEMD_SYSTEM_UNIT_DIR ?= $(shell pkgconf --variable systemd_system_unit_dir systemd)
WKD_FQDN ?= archlinux.org
WKD_BUILD_DIR ?= $(BUILD_DIR)/wkd
KEYRING_FILE=archlinux.gpg
KEYRING_REVOKED_FILE=archlinux-revoked
KEYRING_TRUSTED_FILE=archlinux-trusted
WKD_SYNC_SCRIPT=archlinux-keyring-wkd-sync
WKD_SYNC_SERVICE_IN=archlinux-keyring-wkd-sync.service.in
WKD_SYNC_SERVICE=archlinux-keyring-wkd-sync.service
WKD_SYNC_TIMER=archlinux-keyring-wkd-sync.timer
SYSTEMD_TIMER_DIR=$(SYSTEMD_SYSTEM_UNIT_DIR)/timers.target.wants/
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
	./keyringctl -v $(BUILD_DIR)

wkd: build
	sq -f wkd generate -s $(WKD_BUILD_DIR)/ $(WKD_FQDN) $(BUILD_DIR)/$(KEYRING_FILE)

wkd_inspect: wkd
	for file in $(WKD_BUILD_DIR)/.well-known/openpgpkey/$(WKD_FQDN)/hu/*; do sq inspect $$file; done

wkd_sync_service: wkd_sync/$(WKD_SYNC_SERVICE_IN)
	sed -e 's|SCRIPT_TARGET_DIR|$(SCRIPT_TARGET_DIR)|' wkd_sync/$(WKD_SYNC_SERVICE_IN) > $(BUILD_DIR)/$(WKD_SYNC_SERVICE)

clean:
	rm -rf $(BUILD_DIR) $(WKD_BUILD_DIR)

install: build wkd_sync_service
	install -vDm 644 build/{$(KEYRING_FILE),$(KEYRING_REVOKED_FILE),$(KEYRING_TRUSTED_FILE)} -t $(DESTDIR)$(KEYRING_TARGET_DIR)
	install -vDm 755 wkd_sync/$(WKD_SYNC_SCRIPT) -t $(DESTDIR)$(SCRIPT_TARGET_DIR)
	install -vDm 644 build/$(WKD_SYNC_SERVICE) -t $(DESTDIR)$(SYSTEMD_SYSTEM_UNIT_DIR)
	install -vDm 644 wkd_sync/$(WKD_SYNC_TIMER) -t $(DESTDIR)$(SYSTEMD_SYSTEM_UNIT_DIR)
	install -vdm 755 $(DESTDIR)$(SYSTEMD_TIMER_DIR)
	ln -fsv ../$(WKD_SYNC_TIMER) $(DESTDIR)$(SYSTEMD_TIMER_DIR)/$(WKD_SYNC_TIMER)

uninstall:
	rm -fv $(DESTDIR)$(KEYRING_TARGET_DIR)/{$(KEYRING_FILE),$(KEYRING_REVOKED_FILE),$(KEYRING_TRUSTED_FILE)}
	rmdir -pv --ignore-fail-on-non-empty $(DESTDIR)$(KEYRING_TARGET_DIR)
	rm -v $(DESTDIR)$(SCRIPT_TARGET_DIR)/$(WKD_SYNC_SCRIPT)
	rmdir -pv --ignore-fail-on-non-empty $(DESTDIR)$(SCRIPT_TARGET_DIR)
	rm -v $(DESTDIR)$(SYSTEMD_SYSTEM_UNIT_DIR)/{$(WKD_SYNC_SERVICE),$(WKD_SYNC_TIMER)}
	rmdir -pv --ignore-fail-on-non-empty $(DESTDIR)$(SYSTEMD_SYSTEM_UNIT_DIR)
	rm -v $(DESTDIR)$(SYSTEMD_TIMER_DIR)/$(WKD_SYNC_TIMER)
	rmdir -pv --ignore-fail-on-non-empty $(DESTDIR)$(SYSTEMD_TIMER_DIR)

.PHONY: all lint fmt check test clean install uninstall wkd wkd_inspect
