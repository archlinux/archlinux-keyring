<!--
This template is used when a new main PGP public key needs to be added to the
distribution's keyring.
It is used by users with a valid packager key.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"new main key"
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Add a new main key

## Details

- Username: <!-- Add the @-prefixed username -->
- PGP key ID: <!-- Add the "long format" key ID of the new PGP public key here -->
- Revocation Certificate Holder: <!-- Add the @-prefixed username of the revocation certificate holder -->

<!--
NOTE: Attach the above information as a clearsigned document to this ticket
using a valid packager key of the user.
https://www.gnupg.org/gph/en/manual/x135.html
-->

## Checks

### New key owner

- [ ] The [workflow for adding a new main
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/add-a-new-main-key)
  has been followed
- [ ] The key pair has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is attached to this issue as
  a clearsigned document
- [ ] The revocation certificate has been sent in an encrypted message to the
  revocation certificate holder
- [ ] The public key has been uploaded to the SKS infrastructure

### Keyring maintainer

- [ ] The key pair has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is correct and signed with a
  valid and trusted packager key, which is part of `pacman-key`

### Revocation Certificate Holder

- [ ] The revocation certificate has been [verified
  as working](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/verify-a-revocation-certificate)
  and confirmed in a comment to this issue
- [ ] The revocation certificate has been backed up in a dedicated encrypted backup storage
