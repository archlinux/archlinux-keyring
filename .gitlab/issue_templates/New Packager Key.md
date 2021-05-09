<!--
This template is used when a new packager PGP public key needs to be added to
the distribution's keyring.
It is either used by the sponsor of a new packager or by an existing packager
when adding a new key for themself.
-->
/assign @allan @anthraxx @bluewind @dvzrv @pierre
/label ~"new packager key"
/title New packager key of <!-- MODIFY: Add new packager key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Add a new packager key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the "long format" key ID of the new PGP public key here -->
- Sponsors: <!-- MODIFY: Add the @-prefixed usernames of the sponsors -->
- Application: <!-- MODIFY: Add link to application, if this is the key of a new packager, else remove -->
- Results: <!-- MODIFY: Add link to results of application, if this is the key of a new packager, else remove -->

<!--
NOTE: Attach the above information as a clearsigned document to this ticket.
https://www.gnupg.org/gph/en/manual/x135.html

If this is the key of a new packager, one of their sponsors needs to do the
signature.
If this is a new key of an already existing packager, the packager themself
needs to do the signature.
-->

## Checks

### New key owner

- [ ] The [workflow for adding a new packager
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/add-a-new-packager-key)
  has been followed
- [ ] The key pair contains one user ID with a valid `<username>@archlinux.org` email address
  used for signing
- [ ] The key pair has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is attached to this issue as
  a clearsigned document
- [ ] The public key has been uploaded to the SKS infrastructure

### Main key holders

- [ ] The public key has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The public key has been signed by all main key holders
  - [ ] @allan
  - [ ] @anthraxx
  - [ ] @bluewind
  - [ ] @dvzrv
  - [ ] @pierre

### Keyring maintainer

- [ ] The public key contains one user ID with a valid
  `<username>@archlinux.org` email address used for signing
- [ ] The public key has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is correct and signed with a
  valid and trusted packager key, which is part of `pacman-key`
