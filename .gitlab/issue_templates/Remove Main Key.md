<!--
This template is used when an existing main PGP public key needs to be removed
from the distribution's keyring.
It is used by users with a valid main key or the holder of the revocation
certificate of the main key that is about to be removed.

NOTE: All comment sections with a MODIFY note need to be edited. All checkboxes
in the "Check" section labeled as "Main key holders" need to be checked for the
accompanying merge request to be merged.
-->
/assign @anthraxx @bluewind @diabonas @dvzrv @grazzolini @pierre
/label ~"remove main key"
/title Remove main key of <!-- MODIFY: Add main key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a main key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the output of `gpg --keyid-format long --list-key <MAIN KEY UID> | sed -n '2p' | tr -d ' '` here -->
- Resignation: <!-- MODIFY: Link to resignation of key holder -->

## Checks

### Main key holders

- [ ] There are more than or equal to three valid main keys remaining after
  removal of this key.
- [ ] All packagers have at least three valid main key signatures for their
  packager key after removal of this key.
- [ ] A merge request to [remove the main public
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/remove-a-main-key)
  has been created
