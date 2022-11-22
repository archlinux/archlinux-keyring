<!--
This template is used when a new packager PGP public key needs to be added to
the distribution's keyring.
It is either used by the sponsor of a new packager or by an existing packager
when adding a new key for themself.

NOTE: All comment sections with a MODIFY note need to be edited. All checkboxes
in the "Checks" section labeled as "Owner of new key" need to be checked by the
owner of the new key or by a sponsor of a new packager.
-->
/assign @archlinux/teams/main-key-holders
/label ~"new packager key"
/title New packager key of <!-- MODIFY: Add new packager key holder's username -->
<!--
Please do not remove the above quick actions, which automatically label the
issue and assign relevant users.
-->

# Add a new packager key

## Details

- Username: <!-- MODIFY: Add the @-prefixed username -->
- PGP key ID: <!-- MODIFY: Add the output of `gpg --keyid-format long --list-key <MY UID> | sed -n '2p' | tr -d ' '` here -->
- Sponsors: <!-- MODIFY: Add the @-prefixed usernames of the sponsors -->
- Application: <!-- MODIFY: Add link to application, if this is the key of a new packager, else remove -->
- Results: <!-- MODIFY: Add link to results of application, if this is the key of a new packager, else remove -->
- Previous Key: <!--
  MODIFY: Add the output of `gpg --keyid-format long --list-key <MY PREVIOUS ID> | sed -n '2p' | tr -d ' '` here
  if another packager key exists already, else remove
  -->

<!--
MODIFY: Attach the above information of the details section as a clearsigned
document (see https://www.gnupg.org/gph/en/manual/x135.html) to this ticket.
If a previous (valid and trusted) packager key of the user exists, it needs to
be used for clearsigning the document.
If the key of a new packager is added, one of their sponsors needs to clearsign
the details section.

* Select the above text, copy/paste it into a file (e.g. `details.txt`).
* Make sure to sign with the root certificate of the packager key (not any of
  the subkeys!):
  `gpg --armor --default-key <fingerprint_of_root>! --clearsign details.txt`
* Upload `details.txt` as attachment to this ticket.
-->

## Checks

### Owner of new key

- [ ] The [workflow for adding a new packager
  key](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/workflows/add-a-new-packager-key)
  has been followed
- [ ] The key pair contains one user ID with a valid `<username>@archlinux.org` email address
  used for signing
- [ ] The key pair has been validated according to the [best
  practices](https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/wikis/best-practices#validating-a-key-pair)
- [ ] The data in the [Details](#details) section is attached to this issue as
  a clearsigned document
- [ ] The public key has been uploaded to the pgp.mit.edu and keyserver.ubuntu.com
- [ ] A merge request to add the new public key has been created

### Main key holders

- [ ] The public key has been signed by all main key holders
  - [ ] @anthraxx
  - [ ] @bluewind
  - [ ] @diabonas
  - [ ] @dvzrv
  - [ ] @pierre

### Developers of the archlinux-keyring project
- [ ] The data in the [Details](#details) section is correct and signed with a
  valid and trusted packager key, which is already part of `archlinux-keyring`
