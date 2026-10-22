"""Format v1 compatibility: frozen test vectors and an independent reference decoder.

The vectors in ``tests/vectors/format_v1.json`` were produced once, by Kist 0.2.x, and
must never be regenerated or edited: every Kist 1.x release must open them. The
reference decoder below follows FORMAT.md and uses only the ``cryptography``
library, not Kist's own decryption code, so it checks that the specification
describes what Kist actually writes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
import uuid
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from kist.core import (
    DecryptionError,
    Kist,
    KistScope,
    _KeyBundle,
    decrypt_envelope,
    encrypt_envelope,
    envelope_header_problem,
    git_context,
    profile_from_path,
)
from kist.share import share_context

VECTORS_PATH = Path(__file__).parent / "vectors" / "format_v1.json"
# Changing this hash means changing frozen vectors: that is a compatibility break.
VECTORS_SHA256 = "6c1cf195785b11ac7c06ab9baf575556d0fab6a99dad1228006693112b5cd464"

VECTORS = json.loads(VECTORS_PATH.read_text())
PASSWORD = VECTORS["password"]


def vector(name: str) -> dict:
    return next(v for v in VECTORS["vectors"] if v["name"] == name)


# -- Reference decoder, written from FORMAT.md --------------------------------

def ref_canonical(context: dict) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def ref_open_envelope(envelope: bytes, password: str, context: dict) -> bytes:
    magic, version, cipher, kdf, flags, memory, iterations, lanes = struct.unpack(">4sBBBBIIH", envelope[:18])
    assert (magic, version, cipher, kdf, flags) == (b"KIST", 1, 1, 1, 0)
    assert 19_456 <= memory <= 262_144 and 1 <= iterations <= 10 and 1 <= lanes <= 16
    salt, wrap_nonce, context_hash = envelope[18:34], envelope[34:46], envelope[46:78]
    header = envelope[:78]
    aad = ref_canonical(context)
    assert context_hash == hashlib.sha256(aad).digest()
    wrapped, nonce, ciphertext = envelope[78:126], envelope[126:138], envelope[138:]
    wrapping_key = Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes,
                            memory_cost=memory).derive(password.encode("utf-8"))
    data_key = AESGCM(wrapping_key).decrypt(wrap_nonce, wrapped, b"kist-wrap-v1\x00" + header + aad)
    return AESGCM(data_key).decrypt(nonce, ciphertext, b"kist-content-v1\x00" + header + wrapped + aad)


def ref_open_record(blob: bytes, content_key: bytes, context: dict) -> dict:
    assert blob[:5] == b"KSTR\x01"
    aad = b"KSTR\x01" + ref_canonical(context)
    return json.loads(AESGCM(content_key).decrypt(blob[5:17], blob[17:], aad))


# -- The vectors themselves ----------------------------------------------------

def test_vectors_are_frozen():
    assert hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest() == VECTORS_SHA256


@pytest.mark.parametrize("name", ["git-file-default-scope", "git-file-configured-scope"])
def test_git_file_vectors(name, monkeypatch):
    v = vector(name)
    ctx = v["context"]
    # The context Kist builds today for this file and scope is exactly the frozen one.
    if ctx["repository"] == "local-repository":
        monkeypatch.delenv("KIST_REPOSITORY_ID", raising=False)
    else:
        monkeypatch.setenv("KIST_REPOSITORY_ID", ctx["repository"])
    monkeypatch.setenv("KIST_DIR", "/nonexistent-kist-dir")
    assert profile_from_path(ctx["path"]) == ctx["profile"]
    built = git_context(ctx["profile"], ctx["path"], KistScope(ctx["organization"], ctx["project"]))
    assert built == ctx
    envelope = bytes.fromhex(v["envelope_hex"])
    plaintext = bytes.fromhex(v["plaintext_hex"])
    assert envelope_header_problem(envelope) is None
    assert decrypt_envelope(envelope, PASSWORD, ctx) == plaintext
    assert ref_open_envelope(envelope, PASSWORD, ctx) == plaintext


def test_share_file_vector():
    v = vector("share-file")
    assert share_context("team_a") == v["context"]
    envelope = bytes.fromhex(v["envelope_hex"])
    plaintext = bytes.fromhex(v["plaintext_hex"])
    assert decrypt_envelope(envelope, PASSWORD, v["context"]) == plaintext
    assert ref_open_envelope(envelope, PASSWORD, v["context"]) == plaintext


def test_db_key_bundle_and_record_vector():
    v = vector("database-key-bundle-and-record")
    ids = {k: uuid.UUID(s) for k, s in v["scope_ids"].items()}
    store = Kist("team_a", password=PASSWORD, db_url=None, scope=KistScope("example-org", "project-a"))
    store.organization_id, store.project_id, store.profile_id = ids["organization_id"], ids["project_id"], ids["profile_id"]
    bundle_row, secret_row = v["key_bundles_row"], v["secrets_row"]
    bundle_id = uuid.UUID(bundle_row["id"])

    # Key bundle: a password envelope holding "KKB1" + content key + index key.
    assert store._bundle_context(bundle_id) == v["bundle_context"]
    wrapped = bytes.fromhex(bundle_row["wrapped_bundle_hex"])
    for raw in (decrypt_envelope(wrapped, PASSWORD, v["bundle_context"]),
                ref_open_envelope(wrapped, PASSWORD, v["bundle_context"])):
        assert raw == b"KKB1" + bytes.fromhex(v["content_key_hex"]) + bytes.fromhex(v["index_key_hex"])
    bundle = _KeyBundle(bundle_id, raw[4:36], raw[36:68])

    # Record: Kist opens it through its normal row decoder ...
    blob = bytes.fromhex(secret_row["encrypted_blob_hex"])
    token = bytes.fromhex(secret_row["lookup_token_hex"])
    row = (uuid.UUID(secret_row["id"]), token, bundle_id, secret_row["crypto_version"],
           secret_row["secret_version"], blob)
    assert store._decode_row(bundle, row, v["secret_key"]) == (v["secret_key"], v["secret_value"])

    # ... and so does the reference decoder, with the lookup token recomputed from the spec.
    name_context = {"format": "kist-name-index-v1", **v["scope_ids"], "secret_key": v["secret_key"]}
    assert hmac.new(bundle.index_key, ref_canonical(name_context), hashlib.sha256).digest() == token
    record_context = {"format": "kist-db-record-v1", **v["scope_ids"], "row_id": secret_row["id"],
                      "bundle_id": bundle_row["id"], "lookup_token": token.hex(),
                      "secret_version": str(secret_row["secret_version"]), "crypto_version": "1"}
    assert ref_open_record(blob, bundle.content_key, record_context) == {
        "key": v["secret_key"], "value": v["secret_value"]}


# -- Today's writer still matches the specification ------------------------------

def test_current_writer_matches_reference_decoder():
    ctx = {"format": "kist-git-v1", "organization": "local", "project": "default", "profile": "team_a",
           "repository": "local-repository", "path": "secrets/secrets_team_a.yml"}
    envelope = encrypt_envelope(b"a: 1\n", PASSWORD, ctx)
    assert ref_open_envelope(envelope, PASSWORD, ctx) == b"a: 1\n"
    assert len(envelope) == 78 + 48 + 12 + len(b"a: 1\n") + 16


def test_any_modified_byte_is_rejected():
    v = vector("git-file-default-scope")
    envelope = bytearray.fromhex(v["envelope_hex"])
    # One byte in each region: salt, wrapped key, content nonce, ciphertext.
    for offset in (20, 80, 130, len(envelope) - 1):
        tampered = bytearray(envelope)
        tampered[offset] ^= 0x01
        with pytest.raises((DecryptionError, InvalidTag)):
            decrypt_envelope(bytes(tampered), PASSWORD, v["context"])


def test_context_is_bound():
    v = vector("git-file-default-scope")
    other = {**v["context"], "path": "secrets/other.yml"}
    with pytest.raises(DecryptionError):
        decrypt_envelope(bytes.fromhex(v["envelope_hex"]), PASSWORD, other)
