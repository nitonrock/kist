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
