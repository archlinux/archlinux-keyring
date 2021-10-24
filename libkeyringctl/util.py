# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import contextmanager
from os import chdir
from os import getcwd
from pathlib import Path
from re import split
from subprocess import PIPE
from subprocess import CalledProcessError
from subprocess import check_output
from sys import exit
from sys import stderr
from traceback import print_stack
from typing import List
from typing import Union


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


def system(cmd: List[str], exit_on_error: bool = False) -> str:
    """Execute a command using check_output

    Parameters
    ----------
    cmd: A list of strings to be fed to check_output
    exit_on_error: Whether to exit the script when encountering an error (defaults to False)

    Raises
    ------
    CalledProcessError: If not exit_on_error and `check_output()` encounters an error

    Returns
    -------
    The output of cmd
    """

    try:
        return check_output(cmd, stderr=PIPE).decode()
    except CalledProcessError as e:
        stderr.buffer.write(e.stderr)
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
