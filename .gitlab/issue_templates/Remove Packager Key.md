<!--
This template is used when an existing packager PGP public key needs to be
removed from the distribution's keyring.
It is used by users with a valid main key or a valid packager key.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"remove packager key"
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a packager key

## Details

- Username: <!-- Add the @-prefixed username -->
- PGP key ID: <!-- Add the "long format" key ID of the PGP public key here -->
- Resignation: <!-- Link to resignation of key holder -->

## Checks

- [ ] There are no packages left in any of the official repositories, that are
  signed by the key, that is about to be removed.
