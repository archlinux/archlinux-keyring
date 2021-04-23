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

- [ ] The [workflow for adding a new main
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/add-a-new-main-key)
  has been followed
- [ ] The data in the [Details](#details) section is attached to this issue as
  a clearsigned document
- [ ] The revocation certificate holder verified the revocation certificate as
  working in a comment to this issue
- [ ] The public key has been uploaded to the SKS infrastructure
