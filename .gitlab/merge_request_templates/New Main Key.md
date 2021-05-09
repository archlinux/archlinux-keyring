<!--
This template is used when a new main PGP public key needs to be added to the
distribution's keyring.
It is used by users with a valid packager key after all steps in an
accompanying issue (opened with the template "New Main Key") have been
fulfilled.
-->
/assign_reviewer @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"new main key"
/title Add main key of <!-- MODIFY: Add the main key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Add a new main key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the "long format" key ID of the PGP public key here -->

Closes <!-- MODIFY: Add #-prefixed issue number, that will be closed by merging this merge request -->

## Checks

### Keyring maintainer

- [ ] All steps in the accompanying ticket are fulfilled.

### Main key holders

- [ ] The public key has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
