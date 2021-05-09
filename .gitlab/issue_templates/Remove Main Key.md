<!--
This template is used when an existing main PGP public key needs to be removed
from the distribution's keyring.
It is used by users with a valid main key.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"remove main key"
/title Remove main key of <!-- MODIFY: Add main key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a main key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the "long format" key ID of the PGP public key here -->
- Resignation: <!-- MODIFY: Link to resignation of key holder -->

## Checks

### Main key holders

- [ ] There are more than or equal to three valid main keys remaining after
  removal of this key.
- [ ] All packagers have at least three valid main key signatures for their
  packager key after removal of this key.

### Keyring maintainer

- [ ] The key has been revoked by either the revocation certificate holder or
  the main key holder.
