import subprocess
from pathlib import Path

import pytest

BASE_DIR = Path("/home/nitonrock/PycharmProjects")
PROJECTS = ["kist_config_github", "kist_config_gitlab", "kist_config_bitbucket"]


def _get_project_dir(proj_name: str) -> Path:
    proj_dir = BASE_DIR / proj_name
    if not proj_dir.is_dir():
        alt_dir = BASE_DIR / proj_name.replace("_", "-")
        if alt_dir.is_dir():
            return alt_dir
    return proj_dir


@pytest.mark.parametrize("proj_name", PROJECTS)
def test_project_structure_and_ci_configs(proj_name):
    """Verify that all three demo projects exist with proper CI, secrets/ dir, and dev-mode configs."""
    proj_dir = _get_project_dir(proj_name)
    assert proj_dir.is_dir(), f"Project directory {proj_dir} does not exist"

    # Verify pyproject.toml and dev mode
    pyproject_file = proj_dir / "pyproject.toml"
    assert pyproject_file.is_file()
    pyproject_text = pyproject_file.read_text()
    assert 'path = "../kist"' in pyproject_text
    assert 'editable = true' in pyproject_text

    # Verify git attributes & ignore
    assert (proj_dir / ".gitattributes").is_file()
    assert (proj_dir / ".gitignore").is_file()

    # Verify secrets/ directory and yaml files
    secrets_dir = proj_dir / "secrets"
    assert secrets_dir.is_dir()
    assert (secrets_dir / "production.yaml").is_file()
    assert (secrets_dir / "staging.yaml").is_file()

    # Verify absence of unnecessary app.py boilerplate
    assert not (proj_dir / f"src/{proj_name}/app.py").is_file()

    # Verify CI configs based on provider
    if proj_name == "kist_config_github":
        assert (proj_dir / ".github/workflows/leak-guard.yml").is_file()
        assert (proj_dir / ".github/workflows/deploy.yml").is_file()
    elif proj_name == "kist_config_gitlab":
        assert (proj_dir / ".gitlab-ci.yml").is_file()
    elif proj_name == "kist_config_bitbucket":
        assert (proj_dir / "bitbucket-pipelines.yml").is_file()


@pytest.mark.parametrize("proj_name", PROJECTS)
def test_project_test_suite_execution(proj_name):
    """Run pytest inside each sample project to verify full end-to-end integration."""
    proj_dir = _get_project_dir(proj_name)
    res = subprocess.run(
        ["uv", "run", "pytest"],
        cwd=str(proj_dir),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Project {proj_name} pytest failed:\n{res.stdout}\n{res.stderr}"
    assert "4 passed" in res.stdout
