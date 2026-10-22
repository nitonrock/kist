"""Version numbers that must move together with pyproject.toml."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_readme_pypi_badge_matches_version():
    readme = (ROOT / "README.md").read_text()
    badges = re.findall(r"img\.shields\.io/badge/pypi-v([0-9][^-]*)-", readme)
    assert badges == [VERSION], "Update the PyPI badge in README.md to the new version"


def test_ci_templates_pin_current_version():
    pins = []
    for path in (ROOT / "resources").rglob("*.yml"):
        text = path.read_text()
        pins += [(path.name, v) for v in re.findall(r'kist==([0-9][\w.]*)', text)]
        pins += [(path.name, v) for v in re.findall(r'KIST_VERSION: "([^"]+)"', text)]
    assert pins, "templates should pin a Kist version"
    assert all(v == VERSION for _, v in pins), f"Update template pins to {VERSION}: {pins}"


def test_release_workflow_uses_trusted_publishing():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "pypa/gh-action-pypi-publish@" in text
    # Third-party actions are pinned to a full commit SHA, not a movable tag.
    uses = re.findall(r"uses:\s*([\w.-]+/[\w.-]+)@([^\s#]+)", text)
    assert uses, "release workflow should use actions"
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for _, ref in uses), uses
    # No stored token: Trusted Publishing only, and attestations stay on.
    for forbidden in ("password:", "PYPI_API_TOKEN", "UV_PUBLISH_TOKEN", "attestations: false"):
        assert forbidden not in text, forbidden
    assert "permissions: {}" in text
    assert text.count("id-token: write") == 1


def test_ci_matrix_covers_supported_pythons():
    pyproject = (ROOT / "pyproject.toml").read_text()
    minimum = re.search(r'requires-python = ">=3\.(\d+)"', pyproject).group(1)
    classified = sorted(int(m) for m in re.findall(r'Python :: 3\.(\d+)"', pyproject))
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    matrix = re.search(r'python-version: \[([^\]]+)\]', workflow).group(1)
    tested = sorted(int(v.strip().strip('"').split(".")[1]) for v in matrix.split(","))
    assert tested[0] == int(minimum), "CI must test the minimum supported Python"
    assert tested == classified, "classifiers and CI matrix must list the same versions"
    assert "macos-latest" in workflow
