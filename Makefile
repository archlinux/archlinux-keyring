V=20120220

PREFIX = /usr/local

install:
	for k in master/*.asc master/ownertrust.txt packager/*.asc; do install -Dm0644 $$k $(DESTDIR)$(PREFIX)/share/archlinux-keyring/$$k; done

uninstall:
	for k in master/*.asc master/ownertrust.txt in packager/*.as; do rm -f $(DESTDIR)$(PREFIX)/share/archlinux-keyring/$$k; done
	rmdir -p --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/archlinux-keyring/master
	rmdir -p --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/archlinux-keyring/packager

dist:
	git archive --format=tar --prefix=archlinux-keyring-$(V)/ $(V) | gzip -9 > archlinux-keyring-$(V).tar.gz
	gpg --detach-sign --use-agent archlinux-keyring-$(V).tar.gz

upload:
	scp archlinux-keyring-$(V).tar.gz archlinux-keyring-$(V).tar.gz.sig gerolde.archlinux.org:/srv/ftp/other/archlinux-keyring/

.PHONY: install uninstall dist upload
