# SPDX-License-Identifier: GPL-3.0-or-later

from logging import debug
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import Set

from .types import Color
from .types import Fingerprint
from .types import Trust
from .types import Uid
from .util import contains_fingerprint
from .util import get_cert_paths


def certificate_trust_from_paths(sources: Iterable[Path], main_keys: Set[Fingerprint]) -> Dict[Fingerprint, Trust]:
    """Get the trust status of all certificates in a list of paths given by main keys.

    Uses `get_get_certificate_trust` to determine the trust status.

    Parameters
    ----------
    sources: Certificates to acquire the trust status from
    main_keys: Fingerprints of trusted keys used to calculate the trust of the certificates from sources

    Returns
    -------
    A dictionary of fingerprints and their trust level
    """

    sources = get_cert_paths(sources)
    certificate_trusts: Dict[Fingerprint, Trust] = {}

    for certificate in sorted(sources):
        fingerprint = Fingerprint(certificate.name)
        certificate_trusts[fingerprint] = certificate_trust(certificate=certificate, main_keys=main_keys)
    return certificate_trusts


def certificate_trust(certificate: Path, main_keys: Set[Fingerprint]) -> Trust:  # noqa: ignore=C901
    """Get the trust status of a certificates given by main keys.

    main certificates are:
        revoked if:
            - the certificate has been self-revoked (also applies to 3rd party applied revocation certificates)
        full trust if:
            - the certificate is not self-revoked

    regular certificates are:
        full trust if:
            - the certificate is not self-revoked and:
                - any uid contains at least 3 non revoked main key signatures
        marginal trust if:
            - the certificate is not self-revoked and:
                - any uid contains at least 1 but less than 3 non revoked main key signatures
                - no uid contains at least 3 non revoked main key signatures
        unknown trust if:
            - the certificate is not self-revoked and:
                - no uid contains any non revoked main key signature
        revoked if:
            - the certificate has been self-revoked, or
            - no uid contains at least 3 non revoked main key signatures and:
                - any uid contains at least 1 revoked main key signature

    Parameters
    ----------
    certificate: Certificate to acquire the trust status from
    main_keys: Fingerprints of trusted keys used to calculate the trust of the certificates from sources

    Returns
    -------
    Trust level of the certificate
    """

    fingerprint: Fingerprint = Fingerprint(certificate.name)

    revocations: Set[Fingerprint] = set()
    # TODO: what about direct key revocations/signatures?
    for revocation in certificate.glob("revocation/*.asc"):
        issuer: Fingerprint = Fingerprint(revocation.stem)
        if fingerprint.endswith(issuer):
            debug(f"Revoking {fingerprint} due to self-revocation")
            revocations.add(fingerprint)

    if revocations:
        return Trust.revoked

    # main keys are either trusted or revoked
    is_main_certificate = contains_fingerprint(fingerprints=main_keys, fingerprint=fingerprint)
    if is_main_certificate:
        return Trust.full

    uid_trust: Dict[Uid, Trust] = {}
    uids = certificate / "uid"
    for uid_path in uids.iterdir():
        uid: Uid = Uid(uid_path.name)

        # TODO: convert key-id to fingerprint otherwise it may contain duplicates
        revocations = set()
        self_revoked = False
        for revocation in uid_path.glob("revocation/*.asc"):
            issuer = Fingerprint(revocation.stem)
            # self revocation
            if fingerprint.endswith(issuer):
                self_revoked = True
            # main key revocation
            elif contains_fingerprint(fingerprints=main_keys, fingerprint=issuer):
                revocations.add(issuer)

        # TODO: convert key-id to fingerprint otherwise it may contain duplicates
        certifications: Set[Fingerprint] = set()
        for certification in uid_path.glob("certification/*.asc"):
            issuer = Fingerprint(certification.stem)
            # only take main key certifications into account
            if not contains_fingerprint(fingerprints=main_keys, fingerprint=issuer):
                continue
            # do not care about certifications that are revoked
            if contains_fingerprint(fingerprints=revocations, fingerprint=issuer):
                continue
            certifications.add(issuer)

        # self revoked uid
        if self_revoked:
            debug(f"Certificate {fingerprint} with uid {uid} is self-revoked")
            uid_trust[uid] = Trust.revoked
            continue

        # full trust
        if len(certifications) >= 3:
            uid_trust[uid] = Trust.full
            continue

        # no full trust and contains revocations
        if revocations:
            uid_trust[uid] = Trust.revoked
            continue

        # marginal trust
        if certifications:
            uid_trust[uid] = Trust.marginal
            continue

        # no trust
        uid_trust[uid] = Trust.unknown

    for uid, uid_trust_status in uid_trust.items():
        debug(f"Certificate {fingerprint} with uid {uid} has trust level: {uid_trust_status.name}")

    trust: Trust
    # any uid has full trust
    if any(map(lambda t: Trust.full == t, uid_trust.values())):
        trust = Trust.full
    # no uid has full trust but at least one is revoked
    # TODO: only revoked if it contains main key revocations, not just self-revocation
    elif any(map(lambda t: Trust.revoked == t, uid_trust.values())):
        trust = Trust.revoked
    # no uid has full trust or is revoked
    elif any(map(lambda t: Trust.marginal == t, uid_trust.values())):
        trust = Trust.marginal
    else:
        trust = Trust.unknown

    debug(f"Certificate {fingerprint} has trust level: {trust.name}")
    return trust


def trust_icon(trust: Trust) -> str:
    """Returns a single character icon representing the passed trust status

    Parameters
    ----------
    trust: The trust to get an icon for

    Returns
    -------
    The single character icon representing the passed trust status
    """
    if trust == Trust.revoked:
        return "✗"
    if trust == Trust.unknown:
        return "~"
    if trust == Trust.marginal:
        return "~"
    if trust == Trust.full:
        return "✓"
    return "?"


def trust_color(trust: Trust) -> Color:
    """Returns a color representing the passed trust status

    Parameters
    ----------
    trust: The trust to get the color of

    Returns
    -------
    The color representing the passed trust status
    """
    color: Color = Color.RED
    if trust == Trust.revoked:
        color = Color.RED
    if trust == Trust.unknown:
        color = Color.YELLOW
    if trust == Trust.marginal:
        color = Color.YELLOW
    if trust == Trust.full:
        color = Color.GREEN
    return color


def format_trust_label(trust: Trust) -> str:
    """Formats a given trust status to a text label including color and icon.

    Parameters
    ----------
    trust: The trust to get the label for

    Returns
    -------
    Text label representing the trust status as literal and icon with colors
    """
    return f"{trust_color(trust).value}{trust_icon(trust)} {trust.name}{Color.RST.value}"
