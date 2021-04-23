<!--
This template is used when an existing main PGP public key needs to be removed
from the distribution's keyring.
It is used by users with a valid main key.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"remove main key"
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a main key

## Details

- Username: <!-- Add the @-prefixed username -->
- PGP key ID: <!-- Add the "long format" key ID of the PGP public key here -->
- Resignation: <!-- Link to resignation of key holder -->

## Checks

- [ ] There are more than or equal to three valid main keys remaining after
  removal of this key.
- [ ] All packagers have at least three valid main key signatures for their
  packager key after removal of this key.
