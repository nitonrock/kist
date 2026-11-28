"""Missing-secret parity on a disposable PostgreSQL database."""
import asyncio
import os
import uuid
from contextlib import nullcontext

import pytest

from kist import Kist, KistScope, MissingKeyError, SecretNotFoundError

_PRIVATE_NAME = "vendor.private.api_key"


@pytest.fixture
def store(request):
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set KIST_TEST_DATABASE_URL to a disposable PostgreSQL database.")
    reader = Kist(profile_name="default", password="missing-secret-test-password", db_url=url,
                  scope=KistScope(organization="kist-missing-tests", project=uuid.uuid4().hex))
    reader.init_db()
    reader.get_or_create_scope()
    if request.param:
        reader.set("present", None)
    try:
        yield reader, request.param
    finally:
        reader.delete_profile()


def check(error):
    assert isinstance(error, KeyError)
    assert not isinstance(error, MissingKeyError)
    assert error.reason_code == "secret_not_found"
    assert error.phase == "query"
    assert error.__context__ is None
    assert error.__cause__ is None
    assert _PRIVATE_NAME not in str(error)
    assert _PRIVATE_NAME not in repr(error.args)
    assert _PRIVATE_NAME not in repr(vars(error))


@pytest.mark.parametrize("store", [False, True], indirect=True, ids=["no_bundle", "absent_row"])
@pytest.mark.parametrize("kind", ["sync", "sync_session", "async", "async_session"])
def test_postgres_missing_secret_parity_and_recovery(store, kind):
    source, has_bundle = store

    async def run():
        context = source.async_session() if kind.endswith("session") else nullcontext(source.as_async())
        async with context as reader:
            with pytest.raises(SecretNotFoundError) as caught:
                await reader.get(_PRIVATE_NAME, timeout=2)
            check(caught.value)
            with pytest.raises(SecretNotFoundError) as caught:
                await reader.get_many([_PRIVATE_NAME], timeout=2)
            check(caught.value)
            assert await reader.get_many([_PRIVATE_NAME], default=None, timeout=2) == {
                _PRIVATE_NAME: None}
            if has_bundle:
                default = object()
                assert await reader.get("present", timeout=2) is None
                assert await reader.get_many(["present", _PRIVATE_NAME], default=default) == {
                    "present": None, _PRIVATE_NAME: default}
            password = reader._sync.password
            reader._sync.password = None
            try:
                with pytest.raises(MissingKeyError):
                    await reader.get_many([_PRIVATE_NAME], default=None)
            finally:
                reader._sync.password = password

    if kind.startswith("async"):
        asyncio.run(run())
        return
    context = source.session() if kind.endswith("session") else nullcontext(source)
    with context as reader:
        with pytest.raises(SecretNotFoundError) as caught:
            reader.get(_PRIVATE_NAME, timeout=2)
        check(caught.value)
        with pytest.raises(SecretNotFoundError) as caught:
            reader.get_many([_PRIVATE_NAME], timeout=2)
        check(caught.value)
        assert reader.get_many([_PRIVATE_NAME], default=None, timeout=2) == {_PRIVATE_NAME: None}
        if has_bundle:
            default = object()
            assert reader.get("present", timeout=2) is None
            assert reader.get_many(["present", _PRIVATE_NAME], default=default) == {
                "present": None, _PRIVATE_NAME: default}
        backing = reader._reader if kind.endswith("session") else reader
        password = backing.password
        backing.password = None
        try:
            with pytest.raises(MissingKeyError):
                reader.get_many([_PRIVATE_NAME], default=None)
        finally:
            backing.password = password
