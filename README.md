# archlinux-keyring

The archlinux-keyring project holds PGP packet material and tooling
(`keyringctl`) to create the distribution keyring for Arch Linux.
The keyring is used by pacman to establish the web of trust for the packagers
of the distribution.

The PGP packets describing the main signing keys can be found below the
[keyring/main](keyring/main) directory, while those of the packagers are located below the
[keyring/packager](keyring/packager) directory.

## Requirements

The following packages need to be installed to be able to create a PGP keyring
from the provided data structure and to install it:

* make
* python
* sequoia-sq

## Installation

To install archlinux-keyring system-wide use the included `Makefile`:

```bash
make install
```

## Contribute

Development of archlinux-keyring takes place on Arch Linux' Gitlab:
https://gitlab.archlinux.org/archlinux/archlinux-keyring.

Please read our distribution-wide [Code of
Conduct](https://terms.archlinux.org/docs/code-of-conduct/) before
contributing, to understand what actions will and will not be tolerated.

Read our [contributing guide](CONTRIBUTING.md) to learn more about how to
provide fixes or improvements for the code base and how to add, update or
remove key material.

Discussion around archlinux-keyring may take place on the [arch-projects
mailing list](https://lists.archlinux.org/listinfo/arch-projects) and in
[#archlinux-projects](ircs://irc.libera.chat/archlinux-projects) on [Libera
Chat](https://libera.chat/).

All past and present authors of archlinux-keyring are listed in
[AUTHORS](AUTHORS.md).

## Releases

[Releases of
archlinux-keyring](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/tags)
are created by its current maintainer [Christian
Hesse](https://gitlab.archlinux.org/eworm). Tags are signed using the PGP key
with the ID `02FD1C7A934E614545849F19A6234074498E9CEE`.

To verify a tag, first import the relevant PGP key:

```bash
gpg --auto-key-locate wkd --search-keys eworm@archlinux.org
```

Afterwards a tag can be verified from a clone of this repository:

```bash
git verify-tag <tag>
```

## License

Archlinux-keyring is licensed under the terms of the **GPL-3.0-or-later** (see
[LICENSE](LICENSE)).
