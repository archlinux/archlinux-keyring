# SPDX-License-Identifier: GPL-3.0-or-later

from collections import defaultdict
from collections.abc import Iterable
from itertools import chain
from logging import debug
from pathlib import Path
from re import escape
from re import match
from re import sub
from shutil import copytree
from subprocess import PIPE
from subprocess import Popen
from tempfile import NamedTemporaryFile
from tempfile import mkdtemp
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from .sequoia import inspect
from .sequoia import keyring_merge
from .sequoia import keyring_split
from .sequoia import latest_certification
from .sequoia import packet_dump_field
from .sequoia import packet_join
from .sequoia import packet_split
from .types import Fingerprint
from .types import Uid
from .types import Username
from .util import system


def is_pgp_fingerprint(string: str) -> bool:
    """Returns whether the passed string looks like a PGP (long) fingerprint

    Parameters
    ----------
    string: Input to consider as a fingerprint

    Returns
    -------
    RWhether string is a fingerprint
    """
    if len(string) not in [16, 40]:
        return False
    return match("^[A-F0-9]+$", string) is not None


def get_cert_paths(paths: Iterable[Path]) -> Set[Path]:
    """Walks a list of paths and resolves all discovered certificate paths

    Parameters
    ----------
    paths: A list of paths to walk and resolve to certificate paths.

    Returns
    -------
    A set of paths to certificates
    """

    # depth first search certificate paths
    cert_paths: Set[Path] = set()
    visit: List[Path] = list(paths)
    while visit:
        path = visit.pop()
        # this level contains a certificate, abort depth search
        if list(path.glob("*.asc")):
            cert_paths.add(path)
            continue
        visit.extend([path for path in path.iterdir() if path.is_dir()])
    return cert_paths


def get_parent_cert_paths(paths: Iterable[Path]) -> Set[Path]:
    """Walks a list of paths upwards and resolves all discovered parent certificate paths

    Parameters
    ----------
    paths: A list of paths to walk and resolve to certificate paths.

    Returns
    -------
    A set of paths to certificates
    """

    # depth first search certificate paths
    cert_paths: Set[Path] = set()
    visit: List[Path] = list(paths)
    while visit:
        node = visit.pop().parent
        # this level contains a certificate, abort depth search
        if "keyring" == node.parent.parent.parent.name:
            cert_paths.add(node)
            continue
        visit.append(node)
    return cert_paths


def transform_username_to_keyring_path(keyring_dir: Path, paths: List[Path]) -> None:
    """Mutates the input sources by transforming passed usernames to keyring paths

    Parameters
    ----------
    keyring_dir: The directory underneath the username needs to exist
    paths: A list of paths to mutate and replace usernames to keyring paths
    """
    for index, source in enumerate(paths):
        if source.exists():
            continue
        packager_source = keyring_dir / source.name
        if not packager_source.exists():
            continue
        paths[index] = packager_source


def transform_fingerprint_to_keyring_path(keyring_root: Path, paths: List[Path]) -> None:
    """Mutates the input sources by transforming passed fingerprints to keyring paths

    Parameters
    ----------
    keyring_root: The keyring root directory to look up fingerprints in
    paths: A list of paths to mutate and replace fingerprints to keyring paths
    """
    for index, source in enumerate(paths):
        if source.exists():
            continue
        if not is_pgp_fingerprint(source.name):
            continue
        fingerprint_paths = list(keyring_root.glob(f"*/*/*{source.name}"))
        if not fingerprint_paths:
            continue
        paths[index] = fingerprint_paths[0].parent


# TODO: simplify to lower complexity
def convert_certificate(  # noqa: ignore=C901
    working_dir: Path,
    certificate: Path,
    keyring_dir: Path,
    name_override: Optional[Username] = None,
    fingerprint_filter: Optional[Set[Fingerprint]] = None,
) -> Path:
    """Convert a single file public key certificate into a decomposed directory structure of multiple PGP packets

    The output directory structure is created per user. The username is derived from the certificate via
    `derive_username_from_fingerprint` or overridden via `name_override`.
    Below the username directory a directory tree describes the public keys components split up into certifications
    and revocations, as well as per subkey and per uid certifications and revocations.

    Parameters
    ----------
    working_dir: The path of the working directory below which to create split certificates
    certificate: The path to a public key certificate
    keyring_dir: The path of the keyring used to try to derive the username from the public key fingerprint
    name_override: An optional string to override the username in the to be created output directory structure
    fingerprint_filter: Optional list of fingerprints of PGP public keys that all certifications will be filtered with

    Raises
    ------
    Exception: If required PGP packets are not found

    Returns
    -------
    The path of the user_dir (which is located below working_dir)
    """

    # root packets
    certificate_fingerprint: Optional[Fingerprint] = None
    pubkey: Optional[Path] = None
    # TODO: direct key certifications are not yet selecting the latest sig, owner may have multiple
    # TODO: direct key certifications are not yet single packet per file
    direct_sigs: Dict[Fingerprint, List[Path]] = defaultdict(list)
    direct_revocations: Dict[Fingerprint, List[Path]] = defaultdict(list)

    # subkey packets
    subkeys: Dict[Fingerprint, Path] = {}
    subkey_bindings: Dict[Fingerprint, List[Path]] = defaultdict(list)
    subkey_revocations: Dict[Fingerprint, List[Path]] = defaultdict(list)

    # uid packets
    uids: Dict[Uid, Path] = {}
    certifications: Dict[Uid, Dict[Fingerprint, List[Path]]] = defaultdict(lambda: defaultdict(list))
    revocations: Dict[Uid, Dict[Fingerprint, List[Path]]] = defaultdict(lambda: defaultdict(list))

    # intermediate variables
    current_packet_mode: Optional[str] = None
    current_packet_fingerprint: Optional[Fingerprint] = None
    current_packet_uid: Optional[Uid] = None

    # XXX: PrimaryKeyBinding

    # TODO: remove 3rd party direct key signatures, seems to be leaked by export-clean

    debug(f"Processing certificate {certificate}")

    for packet in packet_split(working_dir=working_dir, certificate=certificate):
        debug(f"Processing packet {packet.name}")
        if packet.name.endswith("--PublicKey"):
            current_packet_mode = "pubkey"
            current_packet_fingerprint = Fingerprint(packet_dump_field(packet, "Fingerprint"))
            current_packet_uid = None

            certificate_fingerprint = current_packet_fingerprint
            pubkey = packet
        elif packet.name.endswith("--UserID"):
            current_packet_mode = "uid"
            current_packet_fingerprint = None
            current_packet_uid = simplify_user_id(Uid(packet_dump_field(packet, "Value")))

            uids[current_packet_uid] = packet
        elif packet.name.endswith("--PublicSubkey"):
            current_packet_mode = "subkey"
            current_packet_fingerprint = Fingerprint(packet_dump_field(packet, "Fingerprint"))
            current_packet_uid = None

            subkeys[current_packet_fingerprint] = packet
        elif packet.name.endswith("--Signature"):
            if not certificate_fingerprint:
                raise Exception('missing certificate fingerprint for "{packet.name}"')

            issuer: Fingerprint = Fingerprint(packet_dump_field(packet, "Issuer"))
            signature_type = packet_dump_field(packet, "Type")

            if current_packet_mode == "pubkey":
                if not current_packet_fingerprint:
                    raise Exception('missing current packet fingerprint for "{packet.name}"')

                if signature_type == "KeyRevocation" and certificate_fingerprint.endswith(issuer):
                    direct_revocations[issuer].append(packet)
                elif signature_type in ["DirectKey", "GenericCertification"]:
                    direct_sigs[issuer].append(packet)
                else:
                    raise Exception(f"unknown signature type: {signature_type}")
            elif current_packet_mode == "uid":
                if not current_packet_uid:
                    raise Exception('missing current packet uid for "{packet.name}"')

                if signature_type == "CertificationRevocation":
                    revocations[current_packet_uid][issuer].append(packet)
                elif signature_type.endswith("Certification"):
                    if fingerprint_filter is not None and any([fp.endswith(issuer) for fp in fingerprint_filter]):
                        debug(f"The certification by issuer {issuer} is appended as it is found in the filter.")
                        certifications[current_packet_uid][issuer].append(packet)
                    else:
                        debug(f"The certification by issuer {issuer} is not appended because it is not in the filter")
                else:
                    raise Exception(f"unknown signature type: {signature_type}")
            elif current_packet_mode == "subkey":
                if not current_packet_fingerprint:
                    raise Exception('missing current packet fingerprint for "{packet.name}"')

                if signature_type == "SubkeyBinding":
                    subkey_bindings[current_packet_fingerprint].append(packet)
                elif signature_type == "SubkeyRevocation":
                    subkey_revocations[certificate_fingerprint].append(packet)
                else:
                    raise Exception(f"unknown signature type: {signature_type}")
            else:
                raise Exception(f'unknown signature root for "{packet.name}"')
        else:
            raise Exception(f'unknown packet type "{packet.name}"')

    if not certificate_fingerprint:
        raise Exception("missing certificate fingerprint")

    if not pubkey:
        raise Exception("missing certificate public-key")

    name_override = (
        name_override
        or derive_username_from_fingerprint(keyring_dir=keyring_dir, certificate_fingerprint=certificate_fingerprint)
        or Username(certificate.stem)
    )

    user_dir = working_dir / name_override
    key_dir = user_dir / certificate_fingerprint
    key_dir.mkdir(parents=True, exist_ok=True)

    persist_public_key(
        certificate_fingerprint=certificate_fingerprint,
        pubkey=pubkey,
        key_dir=key_dir,
    )

    persist_direct_key_certifications(
        direct_key_certifications=direct_sigs,
        key_dir=key_dir,
    )

    persist_direct_key_revocations(
        direct_key_revocations=direct_revocations,
        key_dir=key_dir,
    )

    persist_subkeys(
        key_dir=key_dir,
        subkeys=subkeys,
    )

    persist_subkey_bindings(
        key_dir=key_dir,
        subkey_bindings=subkey_bindings,
    )

    persist_subkey_revocations(
        key_dir=key_dir,
        subkey_revocations=subkey_revocations,
    )

    persist_uids(
        key_dir=key_dir,
        uids=uids,
    )

    persist_uid_certifications(
        certifications=certifications,
        key_dir=key_dir,
    )

    persist_uid_revocations(
        revocations=revocations,
        key_dir=key_dir,
    )

    return user_dir


def persist_public_key(
    certificate_fingerprint: Fingerprint,
    pubkey: Path,
    key_dir: Path,
) -> None:
    """Persist the Public-Key packet

    Parameters
    ----------
    certificate_fingerprint: The unique fingerprint of the public key
    pubkey: The path to the public key of the root key
    key_dir: The root directory below which the basic key material is persisted
    """

    packets: List[Path] = [pubkey]
    output_file = key_dir / f"{certificate_fingerprint}.asc"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    debug(f"Writing file {output_file} from {[str(packet) for packet in packets]}")
    packet_join(packets, output_file, force=True)


def persist_uids(
    key_dir: Path,
    uids: Dict[Uid, Path],
) -> None:
    """Persist the User IDs that belong to a PublicKey

    The User ID material consists of a single User ID Packet.
    The files are written to a UID specific directory and file below key_dir/uid.

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    uids: The User IDs of a Public-Key (the root key)
    """

    for uid, uid_packet in uids.items():
        output_file = key_dir / "uid" / uid / f"{uid}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {uid_packet}")
        packet_join(packets=[uid_packet], output=output_file, force=True)


def persist_subkeys(
    key_dir: Path,
    subkeys: Dict[Fingerprint, Path],
) -> None:
    """Persist all Public-Subkeys of a root key file to file(s)

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    subkeys: The PublicSubkeys of a key
    """

    for fingerprint, subkey in subkeys.items():
        output_file = key_dir / "subkey" / fingerprint / f"{fingerprint}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {str(subkey)}")
        packet_join(packets=[subkey], output=output_file, force=True)


def persist_subkey_bindings(
    key_dir: Path,
    subkey_bindings: Dict[Fingerprint, List[Path]],
) -> None:
    """Persist all SubkeyBinding of a root key file to file(s)

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    subkey_bindings: The SubkeyBinding signatures of a Public-Subkey
    """

    for fingerprint, bindings in subkey_bindings.items():
        subkey_binding = latest_certification(bindings)
        issuer = packet_dump_field(subkey_binding, "Issuer")
        output_file = key_dir / "subkey" / fingerprint / "certification" / f"{issuer}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {str(subkey_binding)}")
        packet_join(packets=[subkey_binding], output=output_file, force=True)


def persist_subkey_revocations(
    key_dir: Path,
    subkey_revocations: Dict[Fingerprint, List[Path]],
) -> None:
    """Persist the SubkeyRevocations of all Public-Subkeys of a root key to file(s)

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    subkey_revocations: The SubkeyRevocations of PublicSubkeys of a key
    """

    for fingerprint, revocations in subkey_revocations.items():
        revocation = latest_certification(revocations)
        issuer = packet_dump_field(revocation, "Issuer")
        output_file = key_dir / "subkey" / fingerprint / "revocation" / f"{issuer}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {revocation}")
        packet_join(packets=[revocation], output=output_file, force=True)


def persist_direct_key_certifications(
    direct_key_certifications: Dict[Fingerprint, List[Path]],
    key_dir: Path,
) -> None:
    """Persist the signatures directly on a root key (such as DirectKeys or *Certifications without a User ID) to
    file(s)

    Parameters
    ----------
    direct_key_certifications: The direct key certifications to write to file
    key_dir: The root directory below which the Directkeys are persisted
    """

    for issuer, certifications in direct_key_certifications.items():
        output_file = key_dir / "certification" / f"{issuer}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {[str(cert) for cert in certifications]}")
        packet_join(packets=certifications, output=output_file, force=True)


def persist_direct_key_revocations(
    direct_key_revocations: Dict[Fingerprint, List[Path]],
    key_dir: Path,
) -> None:
    """Persist the revocations directly on a root key (such as KeyRevocation) to file(s)

    Parameters
    ----------
    direct_key_revocations: The direct key revocations to write to file
    key_dir: The root directory below which the Directkeys are persisted
    """

    for issuer, certifications in direct_key_revocations.items():
        output_file = key_dir / "revocation" / f"{issuer}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {[str(cert) for cert in certifications]}")
        packet_join(packets=certifications, output=output_file, force=True)


def persist_uid_certifications(
    certifications: Dict[Uid, Dict[Fingerprint, List[Path]]],
    key_dir: Path,
) -> None:
    """Persist the certifications of a root key to file(s)

    The certifications include all CasualCertifications, GenericCertifications, PersonaCertifications and
    PositiveCertifications for all User IDs of the given root key.
    All certifications are persisted in per User ID certification directories below key_dir.

    Parameters
    ----------
    certifications: The certifications to write to file
    key_dir: The root directory below which certifications are persisted
    """

    for uid, uid_certifications in certifications.items():
        for issuer, issuer_certifications in uid_certifications.items():
            certification_dir = key_dir / "uid" / uid / "certification"
            certification_dir.mkdir(parents=True, exist_ok=True)
            certification = latest_certification(issuer_certifications)
            output_file = certification_dir / f"{issuer}.asc"
            debug(f"Writing file {output_file} from {certification}")
            packet_join(packets=[certification], output=output_file, force=True)


def persist_uid_revocations(
    revocations: Dict[Uid, Dict[Fingerprint, List[Path]]],
    key_dir: Path,
) -> None:
    """Persist the revocations of a root key to file(s)

    The revocations include all CertificationRevocations for all User IDs of the given root key.
    All revocations are persisted in per User ID 'revocation' directories below key_dir.

    Parameters
    ----------
    revocations: The revocations to write to file
    key_dir: The root directory below which revocations will be persisted
    """

    for uid, uid_revocations in revocations.items():
        for issuer, issuer_revocations in uid_revocations.items():
            revocation_dir = key_dir / "uid" / uid / "revocation"
            revocation_dir.mkdir(parents=True, exist_ok=True)
            revocation = latest_certification(issuer_revocations)
            output_file = revocation_dir / f"{issuer}.asc"
            debug(f"Writing file {output_file} from {revocation}")
            packet_join(packets=[revocation], output=output_file, force=True)


def simplify_user_id(user_id: Uid) -> Uid:
    """Simplify the User ID string to contain more filesystem friendly characters

    Parameters
    ----------
    user_id: A User ID string (e.g. 'Foobar McFooface <foobar@foo.face>')

    Returns
    -------
    The simplified representation of user_id
    """

    user_id_str: str = user_id.replace("@", "_at_")
    user_id_str = sub("[<>]", "", user_id_str)
    user_id_str = sub("[" + escape(r" !@#$%^&*()_-+=[]{}\|;:,.<>/?") + "]", "_", user_id_str)
    return Uid(user_id_str)


def derive_username_from_fingerprint(keyring_dir: Path, certificate_fingerprint: Fingerprint) -> Optional[Username]:
    """Attempt to derive the username of a public key fingerprint from a keyring directory

    Parameters
    ----------
    keyring_dir: The directory in which to look up a username
    certificate_fingerprint: The public key fingerprint to derive the username from

    Raises
    ------
    Exception: If more than one username is found (a public key can only belong to one individual)

    Returns
    -------
    A string representing the username a public key certificate belongs to, None otherwise
    """

    matches = list(keyring_dir.glob(f"*/*{certificate_fingerprint}"))

    if len(matches) > 1:
        raise Exception(
            f"More than one username found in {keyring_dir} when probing for fingerprint '{certificate_fingerprint}': "
            f"{matches}"
        )
    elif not matches:
        debug(f"Can not derive username from target directory for fingerprint {certificate_fingerprint}")
        return None
    else:
        username = matches[0].parent.stem
        debug(
            f"Successfully derived username '{username}' from target directory for fingerprint "
            f"{certificate_fingerprint}"
        )
        return Username(username)


def convert(
    working_dir: Path,
    keyring_root: Path,
    source: Iterable[Path],
    target_dir: Path,
    name_override: Optional[Username] = None,
) -> Path:
    """Convert a path containing PGP certificate material to a decomposed directory structure

    Any input is first split by `keyring_split()` into individual certificates.

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up accepted fingerprints for certifications
    source: A path to a file or directory to decompose
    target_dir: A directory path to write the new directory structure to
    name_override: An optional username override for the call to `convert_certificate()`

    Returns
    -------
    The directory that contains the resulting directory structure (target_dir)
    """

    directories: List[Path] = []
    keys: Iterable[Path] = set(chain.from_iterable(map(lambda s: s.iterdir() if s.is_dir() else [s], source)))

    fingerprint_filter = set(
        get_fingerprints(
            working_dir=working_dir,
            sources=source,
            paths=[keyring_root] if keyring_root.exists() else [],
        ).keys()
    )

    for key in keys:
        for cert in keyring_split(working_dir=working_dir, keyring=key, preserve_filename=True):
            directories.append(
                convert_certificate(
                    working_dir=working_dir,
                    certificate=cert,
                    keyring_dir=target_dir,
                    name_override=name_override,
                    fingerprint_filter=fingerprint_filter,
                )
            )

    for path in directories:
        (target_dir / path.name).mkdir(parents=True, exist_ok=True)
        copytree(src=path, dst=(target_dir / path.name), dirs_exist_ok=True)

    return target_dir


def get_trusted_and_revoked_certs(certs: List[Path]) -> Tuple[List[Fingerprint], List[Fingerprint]]:
    """Get the fingerprints of all trusted and all self revoked public keys in a directory

    Parameters
    ----------
    certs: The certificates to trust

    Returns
    -------
    A tuple with the first item containing the fingerprints of all public keys and the second item containing the
    fingerprints of all self-revoked public keys
    """

    all_certs: List[Fingerprint] = []
    revoked_certs: List[Fingerprint] = []

    # TODO: what about direct key revocations/signatures?

    debug(f"Retrieving trusted and self-revoked certificates from {[str(cert_dir) for cert_dir in certs]}")

    for cert_dir in sorted(get_cert_paths(certs)):
        cert_fingerprint = Fingerprint(cert_dir.stem)
        all_certs.append(cert_fingerprint)
        for revocation_cert in cert_dir.glob("revocation/*.asc"):
            if cert_fingerprint.endswith(revocation_cert.stem):
                debug(f"Revoking {cert_fingerprint} due to self-revocation")
                revoked_certs.append(cert_fingerprint)

    trusted_keys = [cert for cert in all_certs if cert not in revoked_certs]

    return trusted_keys, revoked_certs


def export_ownertrust(certs: List[Path], output: Path) -> Tuple[List[Fingerprint], List[Fingerprint]]:
    """Export ownertrust from a set of keys and return the trusted and revoked fingerprints

    The output file format is compatible with `gpg --import-ownertrust` and lists the main fingerprint ID of all
    non-revoked keys as fully trusted.
    The exported file is used by pacman-key when importing a keyring (see
    https://man.archlinux.org/man/pacman-key.8#PROVIDING_A_KEYRING_FOR_IMPORT).

    Parameters
    ----------
    certs: The certificates to trust
    output: The file path to write to
    """

    trusted_certs, revoked_certs = get_trusted_and_revoked_certs(certs=certs)

    with open(file=output, mode="w") as trusted_certs_file:
        for cert in sorted(set(trusted_certs)):
            debug(f"Writing {cert} to {output}")
            trusted_certs_file.write(f"{cert}:4:\n")

    return trusted_certs, revoked_certs


def export_revoked(certs: List[Path], main_keys: List[Fingerprint], output: Path, min_revoker: int = 1) -> None:
    """Export the PGP revoked status from a set of keys

    The output file contains the fingerprints of all self-revoked keys and all keys for which at least two revocations
    by any main key exist.
    The exported file is used by pacman-key when importing a keyring (see
    https://man.archlinux.org/man/pacman-key.8#PROVIDING_A_KEYRING_FOR_IMPORT).

    Parameters
    ----------
    certs: A list of directories with keys to check for their revocation status
    main_keys: A list of strings representing the fingerprints of (current and/or revoked) main keys
    output: The file path to write to
    min_revoker: The minimum amount of revocation certificates on a User ID from any main key to deem a public key as
        revoked
    """

    trusted_certs, revoked_certs = get_trusted_and_revoked_certs(certs=certs)

    debug(f"Retrieving certificates revoked by main keys from {[str(cert_dir) for cert_dir in certs]}")
    foreign_revocations: Dict[Fingerprint, Set[Fingerprint]] = defaultdict(set)
    for cert_dir in sorted(get_cert_paths(certs)):
        fingerprint = Fingerprint(cert_dir.name)
        debug(f"Inspecting public key {fingerprint}")
        for revocation_cert in cert_dir.glob("uid/*/revocation/*.asc"):
            revocation_fingerprint = Fingerprint(revocation_cert.stem)
            foreign_revocations[fingerprint].update(
                [revocation_fingerprint for main_key in main_keys if main_key.endswith(revocation_fingerprint)]
            )

        # TODO: find a better (less naive) approach, as this would also match on public certificates,
        # where some UIDs are signed and others are revoked
        if len(foreign_revocations[fingerprint]) >= min_revoker:
            debug(
                f"Revoking {cert_dir.name} due to {set(foreign_revocations[fingerprint])} " "being main key revocations"
            )
            revoked_certs.append(fingerprint)

    with open(file=output, mode="w") as trusted_certs_file:
        for cert in sorted(set(revoked_certs)):
            debug(f"Writing {cert} to {output}")
            trusted_certs_file.write(f"{cert}\n")


def get_fingerprints_from_keyring_files(working_dir: Path, source: Iterable[Path]) -> Dict[Fingerprint, Username]:
    """Get all fingerprints of PGP public keys from import file(s)

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    source: The path to a source file or directory containing keyrings

    Returns
    -------
    A dict of all fingerprints and their usernames of PGP public keys below path
    """

    fingerprints: Dict[Fingerprint, Username] = {}
    keys: Iterable[Path] = set(chain.from_iterable(map(lambda s: s.iterdir() if s.is_dir() else [s], source)))

    for key in keys:
        for certificate in keyring_split(working_dir=working_dir, keyring=key, preserve_filename=True):
            for packet in packet_split(working_dir=working_dir, certificate=certificate):
                if packet.name.endswith("--PublicKey"):
                    fingerprints[Fingerprint(packet_dump_field(packet, "Fingerprint"))] = Username(certificate.stem)

    debug(f"Fingerprints of PGP public keys in {source}: {fingerprints}")
    return fingerprints


def get_fingerprints_from_certificate_directory(
    paths: List[Path], prefix: str = "", postfix: str = ""
) -> Dict[Fingerprint, Username]:
    """Get all fingerprints of PGP public keys from decomposed directory structures

    Parameters
    ----------
    paths: The path to a decomposed directory structure
    prefix: Prefix to add to each username
    postfix: Postfix to add to each username

    Returns
    -------
    A dict of all fingerprints and their usernames of PGP public keys below path
    """

    fingerprints: Dict[Fingerprint, Username] = {}
    for cert in sorted(get_cert_paths(paths)):
        fingerprints[Fingerprint(cert.name)] = Username(f"{prefix}{cert.parent.name}{postfix}")

    debug(f"Fingerprints of PGP public keys in {paths}: {fingerprints}")
    return fingerprints


def get_fingerprints(working_dir: Path, sources: Iterable[Path], paths: List[Path]) -> Dict[Fingerprint, Username]:
    """Get the fingerprints of PGP public keys from input paths and decomposed directory structures

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    sources: A list of directories or files from which to read PGP keyring information
    paths: A list of paths that identify decomposed PGP data in directory structures

    Returns
    -------
    A dict of all fingerprints and their usernames of PGP public keys below path
    """

    fingerprints: Dict[Fingerprint, Username] = {}

    fingerprints.update(
        get_fingerprints_from_keyring_files(
            working_dir=working_dir,
            source=sources,
        )
    )

    fingerprints.update(get_fingerprints_from_certificate_directory(paths=paths))

    return fingerprints


def get_packets_from_path(path: Path) -> List[Path]:
    """Collects packets from one level by appending the root, certifications and revocations.

    Parameters
    ----------
    path: Filesystem path used to collect the packets from

    Returns
    -------
    A list of packets ordered by root, certification, revocation
    """
    if not path.exists():
        return []

    packets: List[Path] = []
    packets += sorted(path.glob("*.asc"))
    certifications = path / "certification"
    if certifications.exists():
        packets += sorted(certifications.glob("*.asc"))
    revocations = path / "revocation"
    if revocations.exists():
        packets += sorted(revocations.glob("*.asc"))
    return packets


def get_packets_from_listing(path: Path) -> List[Path]:
    """Collects packets from a listing of directories holding one level each by calling `get_get_packets_from_path`.

    Parameters
    ----------
    path: Filesystem path used as listing to collect the packets from

    Returns
    -------
    A list of packets ordered by root, certification, revocation for each level
    """
    if not path.exists():
        return []

    packets: List[Path] = []
    for sub_path in sorted(path.iterdir()):
        packets += get_packets_from_path(sub_path)
    return packets


def export(
    working_dir: Path,
    keyring_root: Path,
    sources: Optional[List[Path]] = None,
    output: Optional[Path] = None,
) -> Optional[str]:
    """Export all provided PGP packet files to a single output file

    If sources contains directories, any .asc files below them are considered.

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up username shorthand sources
    sources: A list of username, fingerprint or directories from which to read PGP packet information
        (defaults to `keyring_root`)
    output: An output file that all PGP packet data is written to, return the result instead if None

    Returns
    -------
    The result if no output file has been used
    """

    if not sources:
        sources = [keyring_root]

    # transform shorthand paths to actual keyring paths
    transform_username_to_keyring_path(keyring_dir=keyring_root / "packager", paths=sources)
    transform_fingerprint_to_keyring_path(keyring_root=keyring_root, paths=sources)

    temp_dir = Path(mkdtemp(dir=working_dir, prefix="arch-keyringctl-export-join-")).absolute()
    cert_paths: Set[Path] = get_cert_paths(sources)
    certificates: List[Path] = []

    for cert_dir in sorted(cert_paths):
        packets: List[Path] = []
        packets += get_packets_from_path(cert_dir)
        packets += get_packets_from_listing(cert_dir / "subkey")
        packets += get_packets_from_listing(cert_dir / "uid")

        output_path = temp_dir / f"{cert_dir.name}.asc"
        debug(f"Joining {cert_dir} in {output_path}")
        packet_join(
            packets=packets,
            output=output_path,
            force=True,
        )
        certificates.append(output_path)

    if not certificates:
        return None

    return keyring_merge(certificates, output, force=True)


def build(
    working_dir: Path,
    keyring_root: Path,
    target_dir: Path,
) -> None:
    """Build keyring PGP artifacts alongside ownertrust and revoked status files

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to build the artifacts from
    target_dir: Output directory that all artifacts are written to
    """

    target_dir.mkdir(parents=True, exist_ok=True)

    keyring: Path = target_dir / Path("archlinux.gpg")
    export(working_dir=working_dir, keyring_root=keyring_root, output=keyring)

    [trusted_main_keys, revoked_main_keys] = export_ownertrust(
        certs=[keyring_root / "main"],
        output=target_dir / "archlinux-trusted",
    )
    export_revoked(
        certs=[keyring_root],
        main_keys=trusted_main_keys + revoked_main_keys,
        output=target_dir / "archlinux-revoked",
    )


def list_keyring(keyring_root: Path, sources: Optional[List[Path]] = None, main_keys: bool = False) -> None:
    """List certificates in the keyring

    If sources contains directories, all certificate below them are considered.

    Parameters
    ----------
    keyring_root: The keyring root directory to look up username shorthand sources
    sources: A list of username, fingerprint or directories from which to read PGP packet information
        (defaults to `keyring_root`)
    main_keys: List main keys instead of packager keys (defaults to False)
    """

    keyring_dir = keyring_root / ("main" if main_keys else "packager")

    if not sources:
        sources = list(sorted(keyring_dir.iterdir(), key=lambda path: path.name.casefold()))

    # transform shorthand paths to actual keyring paths
    transform_username_to_keyring_path(keyring_dir=keyring_dir, paths=sources)
    transform_fingerprint_to_keyring_path(keyring_root=keyring_root, paths=sources)

    username_length = max([len(source.name) for source in sources])

    for user_path in sources:
        if is_pgp_fingerprint(user_path.name):
            user_path = user_path.parent
        certificates = [cert.name for cert in user_path.iterdir()]
        print(f"{user_path.name:<{username_length}} {' '.join(certificates)}")


def inspect_keyring(working_dir: Path, keyring_root: Path, sources: Optional[List[Path]]) -> str:
    """Inspect certificates in the keyring and pretty print the data

    If sources contains directories, all certificate below them are considered.

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up username shorthand sources
    sources: A list of username, fingerprint or directories from which to read PGP packet information
        (defaults to `keyring_root`)

    Returns
    -------
    The result of the inspect
    """

    if not sources:
        sources = [keyring_root]

    # transform shorthand paths to actual keyring paths
    transform_username_to_keyring_path(keyring_dir=keyring_root / "packager", paths=sources)
    transform_fingerprint_to_keyring_path(keyring_root=keyring_root, paths=sources)

    with NamedTemporaryFile(dir=working_dir, prefix="packet-", suffix=".asc") as keyring:
        keyring_path = Path(keyring.name)
        export(working_dir=working_dir, keyring_root=keyring_root, sources=sources, output=keyring_path)

        fingerprints: Dict[Fingerprint, Username] = get_fingerprints_from_certificate_directory(
            paths=[keyring_root / "packager"]
        ) | get_fingerprints_from_certificate_directory(paths=[keyring_root / "main"], postfix=" (main)")

        return inspect(
            packet=keyring_path,
            certifications=True,
            fingerprints=fingerprints,
        )


def verify(
    working_dir: Path,
    keyring_root: Path,
    sources: Optional[List[Path]],
    lint_hokey: bool = True,
    lint_sq_keyring: bool = True,
) -> None:
    """Verify certificates against modern expectations using sq-keyring-linter and hokey

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up username shorthand sources
    sources: A list of username, fingerprint or directories from which to read PGP packet information
        (defaults to `keyring_root`)
    lint_hokey: Whether to run hokey lint
    lint_sq_keyring: Whether to run sq-keyring-linter
    """

    if not sources:
        sources = [keyring_root]

    # transform shorthand paths to actual keyring paths
    transform_username_to_keyring_path(keyring_dir=keyring_root / "packager", paths=sources)
    transform_fingerprint_to_keyring_path(keyring_root=keyring_root, paths=sources)

    cert_paths: Set[Path] = get_cert_paths(sources)

    for certificate in sorted(cert_paths):
        print(f"Verify {certificate.name} owned by {certificate.parent.name}")

        with NamedTemporaryFile(
            dir=working_dir, prefix=f"{certificate.parent.name}-{certificate.name}", suffix=".asc"
        ) as keyring:
            keyring_path = Path(keyring.name)
            export(
                working_dir=working_dir,
                keyring_root=keyring_root,
                sources=[certificate],
                output=keyring_path,
            )

            if lint_hokey:
                keyring_fd = Popen(("sq", "dearmor", f"{str(keyring_path)}"), stdout=PIPE)
                print(system(["hokey", "lint"], _stdin=keyring_fd.stdout), end="")
            if lint_sq_keyring:
                print(system(["sq-keyring-linter", f"{str(keyring_path)}"]), end="")
