<!--
This template is used when a new main PGP public key needs to be added to the
distribution's keyring.
It is used by users with a valid packager key.

NOTE: All comment sections with a MODIFY note need to be edited. All checkboxes
in the "Checks" section labeled as "Owner of new key" need to be checked by the
owner of the new key.
-->
/assign @anthraxx @bluewind @diabonas @dvzrv @grazzolini @pierre
/label ~"new main key"
/title New main key of <!-- MODIFY: Add new main key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Add a new main key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the output of `gpg --keyid-format long --list-key <MY UID> | sed -n '2p' | tr -d ' '` here -->
- Revocation Certificate Holder: <!-- MODIFY: Add the @-prefixed username of the revocation certificate holder -->

<!--
MODIFY: Attach the above information of the details section as a clearsigned
document (see https://www.gnupg.org/gph/en/manual/x135.html) to this ticket
using a valid packager key of the user:

* Select the above text, copy/paste it into a file (e.g. `details.txt`).
* Make sure to sign with the root certificate of the packager key (not any of
  the subkeys!):
  `gpg --armor --default-key <fingerprint_of_root>! --clearsign details.txt`
* Upload `details.txt` as attachment to this ticket.
-->

## Checks

**NOTE**: The below check boxes **must be** checked before the accompanying
merge request to add the new main key can be merged.

### Owner of new key

- [ ] The [workflow for adding a new main
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/add-a-new-main-key)
  has been followed
- [ ] The key pair has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is attached to this issue as
  a clearsigned document
- [ ] The revocation certificate has been sent in an encrypted message to the
  revocation certificate holder
- [ ] The public key has been uploaded to the pgp.mit.edu and keyserver.ubuntu.com
- [ ] A merge request to add the new public key has been created

### Revocation Certificate Holder

- [ ] The revocation certificate has been [verified
  as working](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/verify-a-revocation-certificate)
  and confirmed in a comment to this issue
- [ ] The revocation certificate has been backed up on a dedicated encrypted backup storage medium

### Main key holders

- [ ] The data in the [Details](#details) section is correct and signed with a
  valid and trusted packager key, which is already part of `archlinux-keyring`
