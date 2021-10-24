# SPDX-License-Identifier: GPL-3.0-or-later

from os import environ
from pathlib import Path
from typing import List

from .git import git_changed_files
from .keyring import get_parent_cert_paths
from .keyring import verify


def ci(working_dir: Path, keyring_root: Path, project_root: Path) -> None:
    """Verify certificates against modern expectations using sq-keyring-linter and hokey

    Currently only newly added certificates will be checked against the expectations as existing
    keys are not all fully compatible with those assumptions.
    New certificates are determined by using $CI_MERGE_REQUEST_DIFF_BASE_SHA as the base,

    Parameters
    ----------
    working_dir: A directory to use for temporary files
    keyring_root: The keyring root directory to look up username shorthand sources
    project_root: Path to the root of the git repository
    """

    ci_merge_request_diff_base = environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    created, deleted, changed = git_changed_files(
        git_path=project_root, base=f"{ci_merge_request_diff_base}", paths=[Path("keyring")]
    )

    added_certificates: List[Path] = list(get_parent_cert_paths(paths=created))

    if added_certificates:
        verify(working_dir=working_dir, keyring_root=keyring_root, sources=added_certificates)
