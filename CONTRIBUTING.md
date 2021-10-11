# Contributing

These are the contribution guidelines for archlinux-keyring.
All code contributions fall under the terms of the GPL-3.0-or-later (see
[LICENSE](LICENSE)).

Any merge request to the repository requires two approvals of authorized
approvers (the current main key holders).

## Keyringctl

The `keyringctl` script is written in typed python, which makes use of
[sequoia](https://sequoia-pgp.org/)'s `sq` command.

The script is type checked, linted and formatted using standard tooling.
When providing a merge request make sure to run `make lint`.

## Key directories

This repository contains PGP packet data, that describes the trusted signing
keys (below [main](main)) and the packager keys (below [packagers](packagers))
of the distribution.

Import of a new main key is done using

```bash
./keyringctl import-main --name <username> <file>
```

Updates to existing main keys is done using

```bash
./keyringctl import-main <file_or_directory>
```

Import of a new packager key is done using

```bash
./keyringctl import-packager --name <username> <file>
```

Updates to existing packager keys is done using

```bash
./keyringctl import-packager <file_or_directory>
```
