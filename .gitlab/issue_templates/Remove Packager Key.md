<!--
This template is used when an existing packager PGP public key needs to be
removed from the distribution's keyring.
It is used by users with a valid main key or a valid packager key.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"remove packager key"
/title Remove packager key of <!-- MODIFY: Add packager key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Remove a packager key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the "long format" key ID of the PGP public key here -->
- Resignation: <!-- MODIFY: Link to resignation of key holder -->

## Checks

- [ ] There are no packages left in any of the official repositories, that are
  signed by the key, that is about to be removed.

### Main key holders

- [ ] All main key holders have revoked their signature for the key and
  published the result on the SKS infrastructure
  - [ ] @allan
  - [ ] @anthraxx
  - [ ] @bluewind
  - [ ] @dvzrv
  - [ ] @pierre
