<!--
This template is used when an existing packager PGP public key needs to be
removed from the distribution's keyring.
It is used by users with a valid main key or a valid packager key.

NOTE: All comment sections with a MODIFY note need to be edited.
-->
/assign @archlinux/teams/main-key-holders
/label ~"remove packager key"
/title Remove packager key of <!-- MODIFY: Add packager key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a packager key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the output of `gpg --keyid-format long --list-key <PACKAGER KEY UID> | sed -n '2p' | tr -d ' '` here -->
- Resignation: <!-- MODIFY: Link to resignation of key holder -->

## Checks

**NOTE**: The below check box **must be** checked before the main key holders
can start to revoke the key.

- [ ] There are [no packages left in any of the official
  repositories](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/Find-packages-signed-by-a-key),
  that are signed by the key or any of its subkeys, which is about to be
  removed.

### Main key holders

All main key holders should revoke their signature(s) for the given key in a
merge request to this repository using `keyringctl`.

- [ ] @anthraxx
- [ ] @bluewind
- [ ] @diabonas
- [ ] @dvzrv
- [ ] @grazzolini
- [ ] @pierre
