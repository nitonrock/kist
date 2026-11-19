"""Connection policy tests; no live database required."""
from unittest.mock import AsyncMock, MagicMock

import psycopg
import pytest

from kist import core

URL = "postgresql://user:secret@example.invalid/kist"


@pytest.fixture(autouse=True)
def isolated_policy(monkeypatch):
    monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    monkeypatch.setattr(core, "enforce_ssl_url", lambda url: url)


def test_defaults_and_no_mutation():
    kwargs = {"application_name": "kist-test"}
    result = core._connection_kwargs(URL, kwargs)
    assert kwargs == {"application_name": "kist-test"}
    assert result == {**kwargs, **core._DEFAULT_CONNECTION_OPTIONS}


def test_url_options_preserved():
    result = core._connection_kwargs(
        URL + "?connect_timeout=4&keepalives=0&tcp_user_timeout=8000", {}
    )
    for name in ("connect_timeout", "keepalives", "tcp_user_timeout"):
        assert name not in result


def test_keyword_options_preserved():
    result = core._connection_kwargs(
        URL + "?connect_timeout=4", {"connect_timeout": 7, "keepalives": 0}
    )
    assert result["connect_timeout"] == 7
    assert result["keepalives"] == 0


def test_environment_timeout_preserved(monkeypatch):
    monkeypatch.setenv("PGCONNECT_TIMEOUT", "6")
    assert "connect_timeout" not in core._connection_kwargs(URL, {})


@pytest.mark.parametrize("name", [
    "sslmode", "sslrootcert", "sslcert", "sslkey", "service", "host", "hostaddr",
])
def test_transport_overrides_rejected(name):
    with pytest.raises(core.KistError):
        core._connection_kwargs(URL, {name: "override"})


def test_sync_connect(monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr(core.psycopg, "connect", connect)
    assert core.safe_db_connect(URL) is connect.return_value
    connect.assert_called_once_with(URL, **core._DEFAULT_CONNECTION_OPTIONS)


@pytest.mark.asyncio
async def test_async_connect(monkeypatch):
    connect = AsyncMock()
    monkeypatch.setattr(core.psycopg.AsyncConnection, "connect", connect)
    assert await core.safe_async_db_connect(URL) is connect.return_value
    connect.assert_awaited_once_with(URL, **core._DEFAULT_CONNECTION_OPTIONS)


def test_sync_error_redaction(monkeypatch):
    connect = MagicMock(side_effect=psycopg.OperationalError("raw secret"))
    monkeypatch.setattr(core.psycopg, "connect", connect)
    with pytest.raises(psycopg.OperationalError) as caught:
        core.safe_db_connect(URL)
    assert "secret" not in str(caught.value)
    assert "raw" not in str(caught.value)


@pytest.mark.asyncio
async def test_async_error_redaction(monkeypatch):
    connect = AsyncMock(side_effect=psycopg.OperationalError("raw secret"))
    monkeypatch.setattr(core.psycopg.AsyncConnection, "connect", connect)
    with pytest.raises(psycopg.OperationalError) as caught:
        await core.safe_async_db_connect(URL)
    assert "secret" not in str(caught.value)
    assert "raw" not in str(caught.value)
