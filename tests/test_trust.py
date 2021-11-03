from pathlib import Path

from libkeyringctl.trust import certificate_trust
from libkeyringctl.types import Trust
from libkeyringctl.types import Uid
from libkeyringctl.types import Username

from .conftest import create_certificate
from .conftest import create_key_revocation
from .conftest import create_uid_certification
from .conftest import test_keyring_certificates
from .conftest import test_main_fingerprints


@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")], keyring_type="main")
def test_certificate_trust_main_key_has_full_trust(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.full == trust


@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")], keyring_type="main")
@create_key_revocation(username=Username("foobar"), keyring_type="main")
def test_certificate_trust_main_key_revoked(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.revoked == trust


@create_certificate(username=Username("main"), uids=[Uid("main <foo@bar.xyz>")])
@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")])
def test_certificate_trust_no_signature_is_unknown(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.unknown == trust


@create_certificate(username=Username("main"), uids=[Uid("main <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")])
@create_uid_certification(issuer=Username("main"), certified=Username("foobar"), uid=Uid("foobar <foo@bar.xyz>"))
def test_certificate_trust_one_signature_is_marginal(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.marginal == trust


@create_certificate(username=Username("main"), uids=[Uid("main <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("not_main"), uids=[Uid("main <foo@bar.xyz>")])
@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")])
@create_uid_certification(issuer=Username("not_main"), certified=Username("foobar"), uid=Uid("foobar <foo@bar.xyz>"))
def test_certificate_trust_one_none_main_signature_gives_no_trust(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.unknown == trust


@create_certificate(username=Username("main1"), uids=[Uid("main1 <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("main2"), uids=[Uid("main2 <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("main3"), uids=[Uid("main3 <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")])
@create_uid_certification(issuer=Username("main1"), certified=Username("foobar"), uid=Uid("foobar <foo@bar.xyz>"))
@create_uid_certification(issuer=Username("main2"), certified=Username("foobar"), uid=Uid("foobar <foo@bar.xyz>"))
@create_uid_certification(issuer=Username("main3"), certified=Username("foobar"), uid=Uid("foobar <foo@bar.xyz>"))
def test_certificate_trust_three_main_signature_gives_full_trust(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.full == trust


@create_certificate(username=Username("main"), uids=[Uid("main <foo@bar.xyz>")], keyring_type="main")
@create_certificate(username=Username("foobar"), uids=[Uid("foobar <foo@bar.xyz>")])
@create_key_revocation(username=Username("foobar"), keyring_type="packager")
def test_certificate_trust_revoked_key(working_dir: Path, keyring_dir: Path) -> None:
    trust = certificate_trust(
        test_keyring_certificates[Username("foobar")][0],
        test_main_fingerprints,
    )
    assert Trust.revoked == trust
