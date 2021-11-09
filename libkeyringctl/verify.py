from logging import debug
from pathlib import Path
from subprocess import PIPE
from subprocess import Popen
from tempfile import NamedTemporaryFile
from typing import List
from typing import Optional
from typing import Set

from libkeyringctl.keyring import export
from libkeyringctl.keyring import get_fingerprints_from_paths
from libkeyringctl.keyring import is_pgp_fingerprint
from libkeyringctl.keyring import transform_fingerprint_to_keyring_path
from libkeyringctl.keyring import transform_username_to_keyring_path
from libkeyringctl.sequoia import packet_dump_field
from libkeyringctl.sequoia import packet_kinds
from libkeyringctl.types import Fingerprint
from libkeyringctl.types import PacketKind
from libkeyringctl.types import Uid
from libkeyringctl.util import get_cert_paths
from libkeyringctl.util import get_fingerprint_from_partial
from libkeyringctl.util import simplify_ascii
from libkeyringctl.util import system


def verify(  # noqa: ignore=C901
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
    all_fingerprints = get_fingerprints_from_paths([keyring_root])

    for certificate in sorted(cert_paths):
        print(f"Verify {certificate.name} owned by {certificate.parent.name}")

        verify_integrity(certificate=certificate, all_fingerprints=all_fingerprints)

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


def verify_integrity(certificate: Path, all_fingerprints: Set[Fingerprint]) -> None:  # noqa: ignore=C901
    if not is_pgp_fingerprint(certificate.name):
        raise Exception(f"Unexpected certificate name for certificate {certificate.name}: {str(certificate)}")

    pubkey = certificate / f"{certificate.name}.asc"
    if not pubkey.is_file():
        raise Exception(f"Missing certificate pubkey {certificate.name}: {str(pubkey)}")

    if not list(certificate.glob("uid/*/*.asc")):
        raise Exception(f"Missing at least one UID for {certificate.name}")

    # check packet files
    for path in certificate.iterdir():
        if path.is_file():
            if path.name != f"{certificate.name}.asc":
                raise Exception(f"Unexpected file in certificate {certificate.name}: {str(path)}")
            kinds: List[PacketKind] = packet_kinds(packet=path)
            if not kinds or len(kinds) > 1:
                raise Exception(f"Unexpected amount of packets in file {str(path)}: {kinds}")
            kind = kinds[0]
            if kind != "Public-Key":
                raise Exception(f"Unexpected packet in file {str(path)}: {kind}")
            fingerprint = packet_dump_field(packet=path, field="Fingerprint")
            if fingerprint != certificate.name:
                raise Exception(f"Unexpected packet fingerprint in file {str(path)}: {fingerprint}")
            debug(f"OK: {path}")
        elif path.is_dir():
            # TODO: check direct key types, multiple
            if "certification" == path.name:
                for sig in path.iterdir():
                    if not sig.is_file():
                        raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(sig)}")
                    if not is_pgp_fingerprint(sig.stem):
                        raise Exception(f"Unexpected file name in certificate {certificate.name}: {str(sig)}")
                    if sig.suffix != ".asc":
                        raise Exception(f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}")
                    kinds = packet_kinds(packet=sig)
                    if not kinds:
                        raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                    if any(filter(lambda kind: not kind == "Signature", kinds)):
                        raise Exception(f"Unexpected packet in file {str(sig)}: {kinds}")
                    debug(f"OK: {path}")
            elif "revocation" == path.name:
                for sig in path.iterdir():
                    if not sig.is_file():
                        raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(sig)}")
                    if not is_pgp_fingerprint(sig.stem):
                        raise Exception(f"Unexpected file name in certificate {certificate.name}: {str(sig)}")
                    if sig.suffix != ".asc":
                        raise Exception(f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}")
                    kinds = packet_kinds(packet=sig)
                    if not kinds or len(kinds) > 1:
                        raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                    kind = kinds[0]
                    if kind != "Signature":
                        raise Exception(f"Unexpected packet in file {str(sig)}: {kind}")
                    fingerprint = packet_dump_field(packet=sig, field="Issuer Fingerprint")
                    if not fingerprint == sig.stem:
                        raise Exception(f"Unexpected packet fingerprint in file {str(sig)}: {fingerprint}")
                    sig_type = packet_dump_field(packet=sig, field="Type")
                    if "KeyRevocation" != sig_type:
                        raise Exception(f"Unexpected packet type in file {str(sig)}: {sig_type}")
                    debug(f"OK: {sig}")
            elif "uid" == path.name:
                for uid in path.iterdir():
                    if not uid.is_dir():
                        raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(uid)}")
                    uid_packet = uid / f"{uid.name}.asc"
                    if not uid_packet.is_file():
                        raise Exception(f"Missing uid packet for {certificate.name}: {str(uid_packet)}")

                    uid_binding_sig = uid / "certification" / f"{certificate.name}.asc"
                    uid_revocation_sig = uid / "revocation" / f"{certificate.name}.asc"
                    if not uid_binding_sig.is_file() and not uid_revocation_sig:
                        raise Exception(f"Missing uid binding/revocation sig for {certificate.name}: {str(uid)}")

                    for uid_path in uid.iterdir():
                        if uid_path.is_file():
                            if uid_path.name != f"{uid.name}.asc":
                                raise Exception(f"Unexpected file in certificate {certificate.name}: {str(uid_path)}")
                            kinds = packet_kinds(packet=uid_path)
                            if not kinds or len(kinds) > 1:
                                raise Exception(f"Unexpected amount of packets in file {str(uid_path)}: {kinds}")
                            kind = kinds[0]
                            if kind != "User":
                                raise Exception(f"Unexpected packet in file {str(uid_path)}: {kind}")
                            uid_value = Uid(simplify_ascii(packet_dump_field(packet=uid_path, field="Value")))
                            if uid_value != uid.name:
                                raise Exception(f"Unexpected uid in file {str(uid_path)}: {uid_value}")
                        elif not uid_path.is_dir():
                            raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(uid_path)}")
                        elif "certification" == uid_path.name:
                            for sig in uid_path.iterdir():
                                if not sig.is_file():
                                    raise Exception(
                                        f"Unexpected file type in certificate {certificate.name}: {str(sig)}"
                                    )
                                if not is_pgp_fingerprint(sig.stem):
                                    raise Exception(
                                        f"Unexpected file name in certificate {certificate.name}: {str(sig)}"
                                    )
                                if sig.suffix != ".asc":
                                    raise Exception(
                                        f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}"
                                    )
                                kinds = packet_kinds(packet=sig)
                                if not kinds or len(kinds) > 1:
                                    raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                                kind = kinds[0]
                                if kind != "Signature":
                                    raise Exception(f"Unexpected packet in file {str(sig)}: {kind}")
                                issuer = get_fingerprint_from_partial(
                                    fingerprints=all_fingerprints,
                                    fingerprint=Fingerprint(packet_dump_field(packet=sig, field="Issuer")),
                                )
                                if issuer != sig.stem:
                                    raise Exception(f"Unexpected issuer in file {str(sig)}: {issuer}")
                                sig_type = packet_dump_field(packet=sig, field="Type")
                                if not sig_type.endswith("Certification"):
                                    raise Exception(f"Unexpected packet type in file {str(sig)}: {sig_type}")
                                debug(f"OK: {sig}")
                        elif "revocation" == uid_path.name:
                            for sig in uid_path.iterdir():
                                if not sig.is_file():
                                    raise Exception(
                                        f"Unexpected file type in certificate {certificate.name}: {str(sig)}"
                                    )
                                if not is_pgp_fingerprint(sig.stem):
                                    raise Exception(
                                        f"Unexpected file name in certificate {certificate.name}: {str(sig)}"
                                    )
                                if sig.suffix != ".asc":
                                    raise Exception(
                                        f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}"
                                    )
                                kinds = packet_kinds(packet=sig)
                                if not kinds or len(kinds) > 1:
                                    raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                                kind = kinds[0]
                                if kind != "Signature":
                                    raise Exception(f"Unexpected packet in file {str(sig)}: {kind}")
                                issuer = get_fingerprint_from_partial(
                                    fingerprints=all_fingerprints,
                                    fingerprint=Fingerprint(packet_dump_field(packet=sig, field="Issuer")),
                                )
                                if issuer != sig.stem:
                                    raise Exception(f"Unexpected issuer in file {str(sig)}: {issuer}")
                                sig_type = packet_dump_field(packet=sig, field="Type")
                                if sig_type != "CertificationRevocation":
                                    raise Exception(f"Unexpected packet type in file {str(sig)}: {sig_type}")
                                debug(f"OK: {sig}")
                        else:
                            raise Exception(f"Unexpected directory in certificate {certificate.name}: {str(uid_path)}")
                        debug(f"OK: {uid_path}")
                    debug(f"OK: {uid}")
            elif "subkey" == path.name:
                for subkey in path.iterdir():
                    if not subkey.is_dir():
                        raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(subkey)}")
                    if not is_pgp_fingerprint(subkey.name):
                        raise Exception(f"Unexpected file name in certificate {certificate.name}: {str(subkey)}")
                    subkey_packet = subkey / f"{subkey.name}.asc"
                    if not subkey_packet.is_file():
                        raise Exception(f"Missing subkey packet for {certificate.name}: {str(subkey_packet)}")

                    subkey_binding_sig = subkey / "certification" / f"{certificate.name}.asc"
                    subkey_revocation_sig = subkey / "revocation" / f"{certificate.name}.asc"
                    if not subkey_binding_sig.is_file() and not subkey_revocation_sig:
                        raise Exception(f"Missing subkey binding/revocation sig for {certificate.name}: {str(subkey)}")

                    for subkey_path in subkey.iterdir():
                        if subkey_path.is_file():
                            if subkey_path.name != f"{subkey.name}.asc":
                                raise Exception(
                                    f"Unexpected file in certificate {certificate.name}: {str(subkey_path)}"
                                )
                            kinds = packet_kinds(packet=subkey_path)
                            if not kinds or len(kinds) > 1:
                                raise Exception(f"Unexpected amount of packets in file {str(subkey_path)}: {kinds}")
                            kind = kinds[0]
                            if kind != "Public-Subkey":
                                raise Exception(f"Unexpected packet in file {str(subkey_path)}: {kind}")
                            fingerprint = packet_dump_field(packet=subkey_path, field="Fingerprint")
                            if fingerprint != subkey_path.stem:
                                raise Exception(
                                    f"Unexpected packet fingerprint in file {str(subkey_path)}: {fingerprint}"
                                )
                        elif not subkey_path.is_dir():
                            raise Exception(
                                f"Unexpected file type in certificate {certificate.name}: {str(subkey_path)}"
                            )
                        elif "certification" == subkey_path.name:
                            for sig in subkey_path.iterdir():
                                if not sig.is_file():
                                    raise Exception(
                                        f"Unexpected file type in certificate {certificate.name}: {str(sig)}"
                                    )
                                if not is_pgp_fingerprint(sig.stem):
                                    raise Exception(
                                        f"Unexpected file name in certificate {certificate.name}: {str(sig)}"
                                    )
                                if sig.suffix != ".asc":
                                    raise Exception(
                                        f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}"
                                    )
                                kinds = packet_kinds(packet=sig)
                                if not kinds or len(kinds) > 1:
                                    raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                                kind = kinds[0]
                                if kind != "Signature":
                                    raise Exception(f"Unexpected packet in file {str(sig)}: {kind}")
                                fingerprint = packet_dump_field(packet=sig, field="Issuer Fingerprint")
                                if fingerprint != certificate.name:
                                    raise Exception(f"Unexpected packet fingerprint in file {str(sig)}: {fingerprint}")
                                sig_type = packet_dump_field(packet=sig, field="Type")
                                if sig_type != "SubkeyBinding":
                                    raise Exception(f"Unexpected packet type in file {str(sig)}: {sig_type}")
                        elif "revocation" == subkey_path.name:
                            for sig in subkey_path.iterdir():
                                if not sig.is_file():
                                    raise Exception(
                                        f"Unexpected file type in certificate {certificate.name}: {str(sig)}"
                                    )
                                if not is_pgp_fingerprint(sig.stem):
                                    raise Exception(
                                        f"Unexpected file name in certificate {certificate.name}: {str(sig)}"
                                    )
                                if sig.suffix != ".asc":
                                    raise Exception(
                                        f"Unexpected file suffix in certificate {certificate.name}: {str(sig)}"
                                    )
                                kinds = packet_kinds(packet=sig)
                                if not kinds or len(kinds) > 1:
                                    raise Exception(f"Unexpected amount of packets in file {str(sig)}: {kinds}")
                                kind = kinds[0]
                                if kind != "Signature":
                                    raise Exception(f"Unexpected packet in file {str(sig)}: {kind}")
                                fingerprint = packet_dump_field(packet=sig, field="Issuer Fingerprint")
                                if fingerprint != certificate.name:
                                    raise Exception(f"Unexpected packet fingerprint in file {str(sig)}: {fingerprint}")
                                sig_type = packet_dump_field(packet=sig, field="Type")
                                if sig_type != "SubkeyRevocation":
                                    raise Exception(f"Unexpected packet type in file {str(sig)}: {sig_type}")
                        else:
                            raise Exception(
                                f"Unexpected directory in certificate {certificate.name}: {str(subkey_path)}"
                            )
                        debug(f"OK: {subkey_path}")
            else:
                raise Exception(f"Unexpected directory in certificate {certificate.name}: {str(path)}")
        else:
            raise Exception(f"Unexpected file type in certificate {certificate.name}: {str(path)}")
