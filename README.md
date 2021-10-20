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

## Usage

Import of a new packager key

```bash
./keyringctl import <username>.asc
# alternatively override the username otherwise derived from the filename
./keyringctl import --name <username> <file>
```

Updates to existing packager keys

```bash
# username is automatically derived from the fingerprint
./keyringctl import <file_or_directory>
```

Import of a new main key

```bash
# same options as packager key except mandatory --main
./keyringctl import --main <username>.asc
```

## Installation

To install archlinux-keyring system-wide use the included `Makefile`:

```bash
make install
```

## Contribute

Read our [contributing guide](CONTRIBUTING.md) to learn more about guidelines and
how to provide fixes or improvements for the code base.

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
