V=20120213

PREFIX = /usr/local

install:
	install -dm0755 $(DESTDIR)$(PREFIX)/share/archlinux-keyring/master
	install -dm0755 $(DESTDIR)$(PREFIX)/share/archlinux-keyring/packager
	for k in master/*.asc; do install -m0644 $$k $(DESTDIR)$(PREFIX)/share/archlinux-keyring/master/; done
	for k in packager/*.asc; do install -m0644 $$k $(DESTDIR)$(PREFIX)/share/archlinux-keyring/packager/; done

uninstall:
	for k in master/*.asc; do rm -f $(DESTDIR)$(PREFIX)/share/archlinux-keyring/master/$$k; done
	for k in packager/*.asc; do rm -f $(DESTDIR)$(PREFIX)/share/archlinux-keyring/packager/$$k; done
	rmdir -p --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/archlinux-keyring/master
	rmdir -p --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/archlinux-keyring/packager

dist:
	git archive --format=tar --prefix=archlinux-keyring-$(V)/ $(V) | gzip -9 > archlinux-keyring-$(V).tar.gz
	gpg --detach-sign --use-agent archlinux-keyring-$(V).tar.gz

upload:
	scp archlinux-keyring-$(V).tar.gz archlinux-keyring-$(V).tar.gz.sig gerolde.archlinux.org:/srv/ftp/other/archlinux-keyring/

.PHONY: install uninstall dist upload
