# SPDX-License-Identifier: GPL-3.0-or-later

from collections import defaultdict
from collections.abc import Iterable
from itertools import chain
from logging import debug
from logging import error
from pathlib import Path
from re import match
from shutil import copytree
from tempfile import NamedTemporaryFile
from tempfile import mkdtemp
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from .sequoia import inspect
from .sequoia import keyring_merge
from .sequoia import keyring_split
from .sequoia import latest_certification
from .sequoia import packet_dump_field
from .sequoia import packet_join
from .sequoia import packet_split
from .trust import certificate_trust
from .trust import certificate_trust_from_paths
from .trust import format_trust_label
from .types import Fingerprint
from .types import Trust
from .types import Uid
from .types import Username
from .util import filter_fingerprints_by_trust
from .util import get_cert_paths
from .util import get_fingerprint_from_partial
from .util import simplify_ascii
from .util import transform_fd_to_tmpfile


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
        paths[index] = fingerprint_paths[0]


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
    The path of the key directory (which is located below working_dir below the user_dir)
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
            current_packet_uid = Uid(simplify_ascii(packet_dump_field(packet, "Value")))

            uids[current_packet_uid] = packet
        elif packet.name.endswith("UserAttribute"):
            current_packet_mode = "uattr"
            current_packet_fingerprint = None
            current_packet_uid = None
        elif packet.name.endswith("--PublicSubkey"):
            current_packet_mode = "subkey"
            current_packet_fingerprint = Fingerprint(packet_dump_field(packet, "Fingerprint"))
            current_packet_uid = None

            subkeys[current_packet_fingerprint] = packet
        elif packet.name.endswith("--SecretKey"):
            error(
                "\n###################################################################\n"
                "Do not ever process your private key file!\n"
                "Consider using a hardware token instead of local private key files!\n"
                "###################################################################"
            )
            raise Exception("Secret key detected, aborting")
        elif packet.name.endswith("--Signature"):
            # ignore user attributes and related signatures
            if current_packet_mode == "uattr":
                debug("skipping user attribute signature packet")
                continue

            if not certificate_fingerprint:
                raise Exception('missing certificate fingerprint for "{packet.name}"')

            issuer = get_fingerprint_from_partial(
                fingerprint_filter or set(), Fingerprint(packet_dump_field(packet, "Issuer"))
            )
            if not issuer:
                debug(f"failed to resolve partial fingerprint {issuer}, skipping packet")
                continue

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
                    # TODO: extend fp filter to all certifications
                    # TODO: use contains_fingerprint
                    if fingerprint_filter is None or any([fp.endswith(issuer) for fp in fingerprint_filter]):
                        debug(f"The certification by issuer {issuer} is appended as it is found in the filter.")
                        certifications[current_packet_uid][issuer].append(packet)
                    else:
                        debug(f"The certification by issuer {issuer} is not appended because it is not in the filter")
                else:
                    raise Exception(f"unknown signature type: {signature_type}")
            elif current_packet_mode == "subkey":
                if not current_packet_fingerprint:
                    raise Exception('missing current packet fingerprint for "{packet.name}"')

                issuer = get_fingerprint_from_partial(
                    fingerprint_filter or set(), Fingerprint(packet_dump_field(packet, "Issuer"))
                )
                if issuer != certificate_fingerprint:
                    raise Exception(f"subkey packet does not belong to {certificate_fingerprint}, issuer: {issuer}")

                if signature_type == "SubkeyBinding":
                    subkey_bindings[current_packet_fingerprint].append(packet)
                elif signature_type == "SubkeyRevocation":
                    subkey_revocations[current_packet_fingerprint].append(packet)
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
        issuer=certificate_fingerprint,
    )

    persist_subkey_revocations(
        key_dir=key_dir,
        subkey_revocations=subkey_revocations,
        issuer=certificate_fingerprint,
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

    return key_dir


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
    issuer: Fingerprint,
) -> None:
    """Persist all SubkeyBinding of a root key file to file(s)

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    subkey_bindings: The SubkeyBinding signatures of a Public-Subkey
    issuer: Fingerprint of the issuer
    """

    for fingerprint, bindings in subkey_bindings.items():
        subkey_binding = latest_certification(bindings)
        output_file = key_dir / "subkey" / fingerprint / "certification" / f"{issuer}.asc"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        debug(f"Writing file {output_file} from {str(subkey_binding)}")
        packet_join(packets=[subkey_binding], output=output_file, force=True)


def persist_subkey_revocations(
    key_dir: Path,
    subkey_revocations: Dict[Fingerprint, List[Path]],
    issuer: Fingerprint,
) -> None:
    """Persist the SubkeyRevocations of all Public-Subkeys of a root key to file(s)

    Parameters
    ----------
    key_dir: The root directory below which the basic key material is persisted
    subkey_revocations: The SubkeyRevocations of PublicSubkeys of a key
    issuer: Fingerprint of the issuer
    """

    for fingerprint, revocations in subkey_revocations.items():
        revocation = latest_certification(revocations)
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
    sources: List[Path],
    target_dir: Path,
    name_override: Optional[Username] = None,
) -> Path:
    """Convert a path containing PGP certificate material to a decomposed directory structure

    Any input is first split by `keyring_split()` into individual certificates.

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up accepted fingerprints for certifications
    sources: A path to a file or directory to decompose
    target_dir: A directory path to write the new directory structure to
    name_override: An optional username override for the call to `convert_certificate()`

    Returns
    -------
    The directory that contains the resulting directory structure (target_dir)
    """

    directories: List[Path] = []
    transform_fd_to_tmpfile(working_dir=working_dir, sources=sources)
    keys: Iterable[Path] = set(chain.from_iterable(map(lambda s: s.iterdir() if s.is_dir() else [s], sources)))

    fingerprint_filter = set(
        get_fingerprints(
            working_dir=working_dir,
            sources=sources,
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
        user_dir = path.parent
        (target_dir / user_dir.name).mkdir(parents=True, exist_ok=True)
        copytree(src=user_dir, dst=(target_dir / user_dir.name), dirs_exist_ok=True)

    return target_dir


def export_ownertrust(certs: List[Path], keyring_root: Path, output: Path) -> List[Fingerprint]:
    """Export ownertrust from a set of keys and return the trusted and revoked fingerprints

    The output file format is compatible with `gpg --import-ownertrust` and lists the main fingerprint ID of all
    non-revoked keys as fully trusted.
    The exported file is used by pacman-key when importing a keyring (see
    https://man.archlinux.org/man/pacman-key.8#PROVIDING_A_KEYRING_FOR_IMPORT).

    Parameters
    ----------
    certs: The certificates to trust
    keyring_root: The keyring root directory to get all accepted fingerprints from
    output: The file path to write to

    Returns
    -------
    List of ownertrust fingerprints
    """

    main_trusts = certificate_trust_from_paths(
        sources=certs,
        main_keys=get_fingerprints_from_paths(sources=certs),
        all_fingerprints=get_fingerprints_from_paths([keyring_root]),
    )
    trusted_certs: List[Fingerprint] = filter_fingerprints_by_trust(main_trusts, Trust.full)

    with open(file=output, mode="w") as trusted_certs_file:
        for cert in sorted(set(trusted_certs)):
            debug(f"Writing {cert} to {output}")
            trusted_certs_file.write(f"{cert}:4:\n")

    return trusted_certs


def export_revoked(certs: List[Path], keyring_root: Path, main_keys: Set[Fingerprint], output: Path) -> None:
    """Export the PGP revoked status from a set of keys

    The output file contains the fingerprints of all self-revoked keys and all keys for which at least two revocations
    by any main key exist.
    The exported file is used by pacman-key when importing a keyring (see
    https://man.archlinux.org/man/pacman-key.8#PROVIDING_A_KEYRING_FOR_IMPORT).

    Parameters
    ----------
    certs: A list of directories with keys to check for their revocation status
    keyring_root: The keyring root directory to get all accepted fingerprints from
    main_keys: A list of strings representing the fingerprints of (current and/or revoked) main keys
    output: The file path to write to
    """

    certificate_trusts = certificate_trust_from_paths(
        sources=certs,
        main_keys=main_keys,
        all_fingerprints=get_fingerprints_from_paths([keyring_root]),
    )
    revoked_certs: List[Fingerprint] = filter_fingerprints_by_trust(certificate_trusts, Trust.revoked)

    with open(file=output, mode="w") as revoked_certs_file:
        for cert in sorted(set(revoked_certs)):
            debug(f"Writing {cert} to {output}")
            revoked_certs_file.write(f"{cert}\n")


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
    revocations = path / "revocation"
    packets += sorted(certifications.glob("*.asc")) if certifications.exists() else []
    packets += sorted(revocations.glob("*.asc")) if revocations.exists() else []
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

    trusted_main_keys = export_ownertrust(
        certs=[keyring_root / "main"],
        keyring_root=keyring_root,
        output=target_dir / "archlinux-trusted",
    )
    export_revoked(
        certs=[keyring_root],
        keyring_root=keyring_root,
        main_keys=set(trusted_main_keys),
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

    # resolve all sources to certificate paths
    sources = list(sorted(get_cert_paths(sources), key=lambda path: str(path).casefold()))

    username_length = max([len(source.parent.name) for source in sources])
    for certificate in sources:
        username: Username = Username(certificate.parent.name)
        trust = certificate_trust(
            certificate=certificate,
            main_keys=get_fingerprints_from_paths([keyring_root / "main"]),
            all_fingerprints=get_fingerprints_from_paths([keyring_root]),
        )
        trust_label = format_trust_label(trust=trust)
        print(f"{username:<{username_length}} {certificate.name} {trust_label}")


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


def get_fingerprints_from_paths(sources: Iterable[Path]) -> Set[Fingerprint]:
    """Get the fingerprints of all certificates found in the sources paths.

    Parameters
    ----------
    sources: A list of directories from which to get fingerprints of the certificates.

    Returns
    -------
    The list of all fingerprints obtained from the sources.
    """
    return set([Fingerprint(cert.name) for cert in get_cert_paths(sources)])
