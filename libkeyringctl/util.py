# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import contextmanager
from os import chdir
from os import getcwd
from pathlib import Path
from re import split
from subprocess import STDOUT
from subprocess import CalledProcessError
from subprocess import check_output
from sys import exit
from sys import stderr
from tempfile import mkstemp
from traceback import print_stack
from typing import IO
from typing import AnyStr
from typing import List
from typing import Optional
from typing import Set
from typing import Union

from libkeyringctl.types import Fingerprint


@contextmanager
def cwd(new_dir: Path) -> Iterator[None]:
    """Change to a new current working directory in a context and go back to the previous dir after the context is done

    Parameters
    ----------
    new_dir: A path to change to
    """

    previous_dir = getcwd()
    chdir(new_dir)
    try:
        yield
    finally:
        chdir(previous_dir)


def natural_sort_path(_list: Iterable[Path]) -> Iterable[Path]:
    """Sort an Iterable of Paths naturally

    Parameters
    ----------
    _list: An iterable containing paths to be sorted

    Return
    ------
    An Iterable of paths that are naturally sorted
    """

    def convert_text_chunk(text: str) -> Union[int, str]:
        """Convert input text to int or str

        Parameters
        ----------
        text: An input string

        Returns
        -------
        Either an integer if text is a digit, else text in lower-case representation
        """

        return int(text) if text.isdigit() else text.lower()

    def alphanum_key(key: Path) -> List[Union[int, str]]:
        """Retrieve an alphanumeric key from a Path, that can be used in sorted()

        Parameters
        ----------
        key: A path for which to create a key

        Returns
        -------
        A list of either int or str objects that may serve as 'key' argument for sorted()
        """

        return [convert_text_chunk(c) for c in split("([0-9]+)", str(key.name))]

    return sorted(_list, key=alphanum_key)


def system(cmd: List[str], _stdin: Optional[IO[AnyStr]] = None, exit_on_error: bool = False) -> str:
    """Execute a command using check_output

    Parameters
    ----------
    cmd: A list of strings to be fed to check_output
    _stdin: input fd used for the spawned process
    exit_on_error: Whether to exit the script when encountering an error (defaults to False)

    Raises
    ------
    CalledProcessError: If not exit_on_error and `check_output()` encounters an error

    Returns
    -------
    The output of cmd
    """

    try:
        return check_output(cmd, stderr=STDOUT, stdin=_stdin).decode()
    except CalledProcessError as e:
        stderr.buffer.write(bytes(e.stdout, encoding="utf8"))
        print_stack()
        if exit_on_error:
            exit(e.returncode)
        raise e


def absolute_path(path: str) -> Path:
    """Return the absolute path of a given str

    Parameters
    ----------
    path: A string representing a path

    Returns
    -------
    The absolute path representation of path
    """

    return Path(path).absolute()


def transform_fd_to_tmpfile(working_dir: Path, sources: List[Path]) -> None:
    """Transforms an input list of paths from any file descriptor of the current process to a tempfile in working_dir.

    Using this function on fd inputs allow to pass the content to another process while hidepid is active and /proc
    not visible for the other process.

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    sources: Paths that should be iterated and all fd's transformed to tmpfiles
    """
    for index, source in enumerate(sources):
        if str(source).startswith("/proc/self/fd"):
            file = mkstemp(dir=working_dir, prefix=f"{source.name}", suffix=".fd")[1]
            with open(file, mode="wb") as f:
                f.write(source.read_bytes())
                f.flush()
            sources[index] = Path(file)


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


def contains_fingerprint(fingerprints: Iterable[Fingerprint], fingerprint: Fingerprint) -> bool:
    return any(filter(lambda e: str(e).endswith(fingerprint), fingerprints))
