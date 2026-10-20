"""CI workflow: lock Kist files straight from a filter-less checkout, for many profiles.

Tests whose names contain "database" need KIST_TEST_DATABASE_URL; the rest only need git.
"""

import os
import shutil
import subprocess
import sys
import uuid

import pytest

from kist import Kist, KistScope

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

PASSWORDS = {
    "device": "device-example-password-0123456789abcd",
    "payments": "payments-example-password-0123456789ab",
    "staging": "staging-example-password-0123456789abc",
}
FILES = {
    "secrets/device.yaml": "cloud:\n  api_key: example-device\n",
    "secrets/payments.yaml": "stripe:\n  key: example-pay\n",
    "secrets/eu/staging.yaml": "db:\n  url: example-staging\n",
}
KIST = f'"{sys.executable}" -m kist'


def run(*args, cwd, env=None, check=True):
    return subprocess.run(list(args), cwd=cwd, env=env, capture_output=True, text=True, check=check)


def kist(*args, cwd, env):
    return subprocess.run([sys.executable, "-m", "kist", *args], cwd=cwd, env=env, capture_output=True, text=True)


@pytest.fixture
def org():
    return "ci-" + uuid.uuid4().hex[:12]


@pytest.fixture
def base_env(tmp_path, org):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("KIST_PASSWORD", "KIST_RETIRED", "KIST_ORG", "KIST_PROJECT", "KIST_REPOSITORY"))}
    env.update(HOME=str(tmp_path), KIST_DIR=str(tmp_path / ".kist"), KIST_ORG_ID=org, KIST_PROJECT_ID="ci-test")
    return env


@pytest.fixture
def ci_checkout(tmp_path, base_env):
    """A developer repository with three encrypted profiles, cloned like a CI runner would (no filters)."""
    dev = tmp_path / "dev"
    dev.mkdir()
    env = dict(base_env, **{f"KIST_PASSWORD_{p.upper()}": pw for p, pw in PASSWORDS.items()})
    run("git", "init", "-q", cwd=dev)
    run("git", "config", "user.email", "test@example.invalid", cwd=dev)
    run("git", "config", "user.name", "test", cwd=dev)
    (dev / ".gitattributes").write_text("secrets*.yaml filter=kist diff=kist\n**/secrets/**/*.yaml filter=kist diff=kist\n")
    run("git", "config", "filter.kist.clean", f"{KIST} --clean %f", cwd=dev)
    run("git", "config", "filter.kist.smudge", f"{KIST} --smudge %f", cwd=dev)
    run("git", "config", "filter.kist.required", "true", cwd=dev)
    for path, text in FILES.items():
        (dev / path).parent.mkdir(parents=True, exist_ok=True)
        (dev / path).write_text(text)
    run("git", "add", "-A", cwd=dev, env=env)
    run("git", "commit", "-q", "-m", "init", cwd=dev, env=env)
    ci = tmp_path / "ci"
    run("git", "clone", "-q", str(dev), str(ci), cwd=tmp_path)
    for path in FILES:
        assert (ci / path).read_bytes().startswith(b"KIST")
    return ci


def with_passwords(env, *profiles):
    return dict(env, **{f"KIST_PASSWORD_{p.upper()}": PASSWORDS[p] for p in profiles})


def test_guard_all_files_accepts_encrypted_checkout(ci_checkout, base_env):
    proc = kist("pre-commit-guard", "--all-files", cwd=ci_checkout, env=base_env)
    assert proc.returncode == 0, proc.stderr


def test_guard_all_files_blocks_plaintext_secret(ci_checkout, base_env):
    (ci_checkout / "secrets" / "new.yaml").write_text("token: example-plaintext\n")
    run("git", "add", "secrets/new.yaml", cwd=ci_checkout)      # no Kist filter on CI clones
    proc = kist("pre-commit-guard", "--all-files", cwd=ci_checkout, env=base_env)
    assert proc.returncode == 1
    assert "plaintext protected secret file: secrets/new.yaml" in proc.stderr


def test_guard_all_files_detects_scope_mismatch(ci_checkout, base_env):
    proc = kist("pre-commit-guard", "--all-files", cwd=ci_checkout, env=dict(base_env, KIST_ORG_ID="other"))
    assert proc.returncode == 1
    assert "KIST_ORG_ID" in proc.stderr


def test_read_yaml_for_lock_decrypts_envelope(ci_checkout, base_env, monkeypatch):
    from kist.ci import read_yaml_for_lock

    for key, value in base_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(ci_checkout / "secrets")                    # paths resolve from a subfolder too
    assert read_yaml_for_lock("eu/staging.yaml", "staging", PASSWORDS["staging"]) == FILES["secrets/eu/staging.yaml"]


@pytest.fixture
def db_env(base_env):
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("No disposable PostgreSQL test URL configured")
    env = dict(base_env, KIST_DATABASE_URL=url, KIST_ENV="development", KIST_TLS_MODE="disable")
    Kist("device", PASSWORDS["device"], url, KistScope(env["KIST_ORG_ID"], "ci-test")).init_db()
    return env


def stored(env, profile):
    return Kist(profile, PASSWORDS[profile], env["KIST_DATABASE_URL"], KistScope(env["KIST_ORG_ID"], "ci-test"))


def test_database_lock_all_locks_profiles_with_password_and_skips_others(ci_checkout, db_env):
    proc = kist("lock", "--all", cwd=ci_checkout, env=with_passwords(db_env, "device", "payments"))
    assert proc.returncode == 0, proc.stderr
    assert "2 locked, 1 skipped, 0 failed." in proc.stdout
    assert "skipped  secrets/eu/staging.yaml (no KIST_PASSWORD_STAGING in this job)" in proc.stdout
    assert stored(db_env, "device").get("cloud.api_key") == "example-device"
    assert stored(db_env, "payments").get("stripe.key") == "example-pay"
    assert not stored(db_env, "staging").secret_count()


def test_database_lock_all_require_all_fails_when_a_password_is_missing(ci_checkout, db_env):
    proc = kist("lock", "--all", "--require-all", cwd=ci_checkout, env=with_passwords(db_env, "device"))
    assert proc.returncode == 1


def test_database_lock_all_only_limits_profiles(ci_checkout, db_env):
    env = with_passwords(db_env, "device", "payments", "staging")
    proc = kist("lock", "--all", "--only", "staging", cwd=ci_checkout, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "1 locked, 0 skipped, 0 failed." in proc.stdout
    assert stored(db_env, "staging").get("db.url") == "example-staging"
    assert not stored(db_env, "device").secret_count()


def test_database_lock_single_encrypted_file(ci_checkout, db_env):
    proc = kist("lock", "secrets/payments.yaml", cwd=ci_checkout, env=with_passwords(db_env, "payments"))
    assert proc.returncode == 0, proc.stderr
    assert stored(db_env, "payments").get("stripe.key") == "example-pay"


def test_database_lock_all_fails_on_scope_mismatch(ci_checkout, db_env):
    env = with_passwords(dict(db_env, KIST_PROJECT_ID="wrong-project"), "device")
    proc = kist("lock", "--all", cwd=ci_checkout, env=env)
    assert proc.returncode == 1
    assert "KIST_PROJECT_ID" in proc.stderr


def test_database_lock_all_ignores_generic_password(ci_checkout, db_env):
    proc = kist("lock", "--all", cwd=ci_checkout, env=dict(db_env, KIST_PASSWORD=PASSWORDS["device"]))
    assert proc.returncode == 0, proc.stderr
    assert "0 locked, 3 skipped, 0 failed." in proc.stdout
    assert "generic KIST_PASSWORD is not used by --all" in proc.stdout


def test_database_lock_all_failure_names_password_source(ci_checkout, db_env):
    env = dict(db_env, KIST_PASSWORD_PAYMENTS="wrong-password-0123456789abcdefgh")
    proc = kist("lock", "--all", cwd=ci_checkout, env=env)
    assert proc.returncode == 1
    assert "[password from KIST_PASSWORD_PAYMENTS]" in proc.stderr


def test_git_filter_uses_each_profiles_own_password_despite_generic(tmp_path, base_env, monkeypatch):
    """Regression: an exported KIST_PASSWORD used to encrypt every profile with one password."""
    from kist.ci import read_yaml_for_lock

    kist_dir = tmp_path / ".kist"
    kist_dir.mkdir(mode=0o700)
    for profile, password in PASSWORDS.items():
        (kist_dir / f"pwd_{profile}").write_text(password)
        (kist_dir / f"pwd_{profile}").chmod(0o600)
    dev = tmp_path / "dev"
    dev.mkdir()
    env = dict(base_env, KIST_PASSWORD=PASSWORDS["device"])
    run("git", "init", "-q", cwd=dev)
    run("git", "config", "user.email", "test@example.invalid", cwd=dev)
    run("git", "config", "user.name", "test", cwd=dev)
    (dev / ".gitattributes").write_text("**/secrets/**/*.yaml filter=kist\n")
    run("git", "config", "filter.kist.clean", f"{KIST} --clean %f", cwd=dev)
    run("git", "config", "filter.kist.required", "true", cwd=dev)
    for path, text in FILES.items():
        (dev / path).parent.mkdir(parents=True, exist_ok=True)
        (dev / path).write_text(text)
    run("git", "add", "-A", cwd=dev, env=env)
    for key, value in base_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(dev)
    for path, text in FILES.items():
        blob = subprocess.run(["git", "cat-file", "blob", f":{path}"], capture_output=True, check=True).stdout
        (tmp_path / "blob").write_bytes(blob)
        monkeypatch.setattr("kist.ci.repo_relative", lambda _p, path=path: path)
        profile = path.rsplit("/", 1)[1].removesuffix(".yaml")
        assert read_yaml_for_lock(str(tmp_path / "blob"), profile, PASSWORDS[profile]) == text
