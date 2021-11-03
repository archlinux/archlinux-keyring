from collections import defaultdict
from functools import wraps
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from typing import Any
from typing import Callable
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Set

from pytest import fixture

from libkeyringctl.keyring import convert_certificate
from libkeyringctl.keyring import simplify_user_id
from libkeyringctl.sequoia import certify
from libkeyringctl.sequoia import key_extract_certificate
from libkeyringctl.sequoia import key_generate
from libkeyringctl.sequoia import keyring_merge
from libkeyringctl.sequoia import packet_join
from libkeyringctl.types import Fingerprint
from libkeyringctl.types import Uid
from libkeyringctl.types import Username
from libkeyringctl.util import cwd

test_keys: Dict[Username, List[Path]] = defaultdict(list)
test_key_revocation: Dict[Username, List[Path]] = defaultdict(list)
test_certificates: Dict[Username, List[Path]] = defaultdict(list)
test_keyring_certificates: Dict[Username, List[Path]] = defaultdict(list)
test_main_fingerprints: Set[Fingerprint] = set()


@fixture(autouse=True)
def reset_storage() -> None:
    test_keys.clear()
    test_key_revocation.clear()
    test_certificates.clear()
    test_keyring_certificates.clear()
    test_main_fingerprints.clear()


def create_certificate(
    username: Username,
    uids: List[Uid],
    keyring_type: str = "packager",
    func: Optional[Callable[..., Any]] = None,
) -> Callable[..., Any]:
    def decorator(decorated_func: Callable[..., None]) -> Callable[..., Any]:
        @wraps(decorated_func)
        def wrapper(working_dir: Path, *args: Any, **kwargs: Any) -> None:
            print(username)

            key_directory = working_dir / "secret" / f"{id}"
            key_directory.mkdir(parents=True, exist_ok=True)

            key_file: Path = key_directory / f"{username}.asc"
            key_generate(uids=uids, outfile=key_file)
            test_keys[username].append(key_file)

            certificate_directory = working_dir / "certificate" / f"{id}"
            certificate_directory.mkdir(parents=True, exist_ok=True)

            keyring_root: Path = working_dir / "keyring"
            keyring_root.mkdir(parents=True, exist_ok=True)
            certificate_file: Path = certificate_directory / f"{username}.asc"

            key_extract_certificate(key=key_file, output=certificate_file)
            test_certificates[username].append(certificate_file)

            key_revocation_packet = key_file.parent / f"{key_file.name}.rev"
            key_revocation_joined = key_file.parent / f"{key_file.name}.joined.rev"
            key_revocation_cert = key_file.parent / f"{key_file.name}.cert.rev"
            packet_join(packets=[certificate_file, key_revocation_packet], output=key_revocation_joined)
            keyring_merge(certificates=[key_revocation_joined], output=key_revocation_cert)
            test_key_revocation[username].append(key_revocation_cert)

            target_dir = keyring_root / keyring_type

            decomposed_path: Path = convert_certificate(
                working_dir=working_dir,
                certificate=certificate_file,
                keyring_dir=keyring_root / keyring_type,
            )
            user_dir = decomposed_path.parent
            (target_dir / user_dir.name).mkdir(parents=True, exist_ok=True)
            copytree(src=user_dir, dst=(target_dir / user_dir.name), dirs_exist_ok=True)
            test_keyring_certificates[username].append(target_dir / user_dir.name / decomposed_path.name)

            if "main" == keyring_type:
                test_main_fingerprints.add(Fingerprint(decomposed_path.name))

            decorated_func(working_dir=working_dir, *args, **kwargs)

        return wrapper

    if not func:
        return decorator
    return decorator(func)


def create_uid_certification(
    issuer: Username, certified: Username, uid: Uid, func: Optional[Callable[[Any], None]] = None
) -> Callable[..., Any]:
    def decorator(decorated_func: Callable[..., None]) -> Callable[..., Any]:
        @wraps(decorated_func)
        def wrapper(working_dir: Path, *args: Any, **kwargs: Any) -> None:
            key: Path = test_keys[issuer][0]
            certificate: Path = test_certificates[certified][0]
            fingerprint: Fingerprint = Fingerprint(test_keyring_certificates[certified][0].name)
            issuer_fingerprint: Fingerprint = Fingerprint(test_keyring_certificates[issuer][0].name)
            simplified_uid = simplify_user_id(uid)

            output: Path = (
                working_dir
                / "keyring"
                / "packager"
                / certified
                / fingerprint
                / "uid"
                / simplified_uid
                / "certification"
                / f"{issuer_fingerprint}.asc"
            )
            output.parent.mkdir(parents=True, exist_ok=True)

            certify(key, certificate, uid, output)

            decorated_func(working_dir=working_dir, *args, **kwargs)

        return wrapper

    if not func:
        return decorator
    return decorator(func)


def create_key_revocation(
    username: Username,
    keyring_type: str = "packager",
    func: Optional[Callable[..., Any]] = None,
) -> Callable[..., Any]:
    def decorator(decorated_func: Callable[..., None]) -> Callable[..., Any]:
        @wraps(decorated_func)
        def wrapper(working_dir: Path, *args: Any, **kwargs: Any) -> None:

            revocation = test_key_revocation[username][0]

            keyring_root: Path = working_dir / "keyring"
            keyring_root.mkdir(parents=True, exist_ok=True)
            target_dir = keyring_root / keyring_type

            decomposed_path: Path = convert_certificate(
                working_dir=working_dir,
                certificate=revocation,
                keyring_dir=keyring_root / keyring_type,
            )
            user_dir = decomposed_path.parent
            (target_dir / user_dir.name).mkdir(parents=True, exist_ok=True)
            copytree(src=user_dir, dst=(target_dir / user_dir.name), dirs_exist_ok=True)

            decorated_func(working_dir=working_dir, *args, **kwargs)

        return wrapper

    if not func:
        return decorator
    return decorator(func)


@fixture(scope="function")
def working_dir() -> Generator[Path, None, None]:
    with TemporaryDirectory(prefix="arch-keyringctl-test-") as tempdir:
        path: Path = Path(tempdir)
        with cwd(path):
            yield path


@fixture(scope="function")
def keyring_dir(working_dir: Path) -> Generator[Path, None, None]:
    yield working_dir / "keyring"
