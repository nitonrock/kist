"""``kist export``: copy a committed, encrypted secret file out of Git for embedded builds."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from kist.core import KistError, is_kist_envelope
from kist.file_store import FileKist, _profile_from_git_path

__all__ = ["ExportResult", "export_envelope"]


@dataclass(frozen=True)
class ExportResult:
    output: Path | None  # None when written to stdout
    git_path: str
    profile: str
    revision: str
    size: int
    verified_keys: int | None = None
    working_tree_differs: bool = False


def _git(args: list[str], *, cwd: str | None = None, binary: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False, text=not binary)
    except FileNotFoundError as exc:
        raise KistError("git is not installed or not on PATH.") from exc


def _repo_relative(file: str) -> tuple[str, str]:
    top = _git(["rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        raise KistError("kist export must run inside a Git work tree.")
    toplevel = top.stdout.strip()
    absolute = os.path.realpath(os.path.abspath(file))
    rel = os.path.relpath(absolute, os.path.realpath(toplevel))
    if rel.startswith(".."):
        raise KistError(f"{file} is outside the repository at {toplevel}.")
    return toplevel, Path(rel).as_posix()


def _verify(path: Path, git_path: str, profile: str, repository_id: str | None) -> int:
    with FileKist(path, git_path=git_path, profile_name=profile, repository_id=repository_id, lazy=False) as store:
        return len(store)


def export_envelope(
    file: str,
    output: str | None = None,
    *,
    revision: str = "HEAD",
    staged: bool = False,
    verify: bool = False,
    profile_name: str | None = None,
    repository_id: str | None = None,
    strict: bool = False,
) -> ExportResult:
    """Write the encrypted Git blob for ``file`` to ``output`` (``"-"`` for stdout).

    The blob is read with ``git cat-file`` (no smudge filter), so plaintext is never produced.
    """
    toplevel, git_path = _repo_relative(file)
    profile = profile_name or _profile_from_git_path(git_path)
    spec = f":{git_path}" if staged else f"{revision}:{git_path}"
    where = "the index" if staged else revision

    blob = _git(["cat-file", "blob", spec], cwd=toplevel, binary=True)
    if blob.returncode != 0:
        raise KistError(f"{git_path} is not in {where}. Commit it (or use --staged) before exporting.")
    envelope: bytes = blob.stdout
    if not is_kist_envelope(envelope):
        raise KistError(
            f"{git_path} in {where} is not Kist-encrypted. Run 'kist init' before 'git add', "
            "then re-add the file; check '.gitattributes' with 'kist diagnose'."
        )

    differs = False
    if not staged:
        diff = _git(["diff", "--quiet", revision, "--", git_path], cwd=toplevel)
        differs = diff.returncode == 1
        if differs and strict:
            raise KistError(f"{git_path} has uncommitted changes; commit first or drop --strict.")

    out_path: Path | None = None
    if output == "-":
        if sys.stdout.isatty():
            raise KistError("Refusing to write binary envelope to a terminal; use -o FILE or redirect.")
        sys.stdout.buffer.write(envelope)
        sys.stdout.buffer.flush()
    else:
        out_path = Path(output) if output else Path(f"{profile}.kist")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".kist-export-", dir=out_path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(envelope)
            os.chmod(tmp, 0o644)  # ciphertext; readable by the service user
            os.replace(tmp, out_path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    verified: int | None = None
    if verify:
        if out_path is not None:
            verified = _verify(out_path, git_path, profile, repository_id)
        else:
            with tempfile.NamedTemporaryFile() as handle:
                handle.write(envelope)
                handle.flush()
                verified = _verify(Path(handle.name), git_path, profile, repository_id)

    return ExportResult(out_path, git_path, profile, "index" if staged else revision,
                        len(envelope), verified, differs)
