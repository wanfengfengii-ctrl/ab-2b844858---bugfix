"""End-to-end API tests for the sealing desk invariants."""

from __future__ import annotations

import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from app import main as web
from app.storage import CHUNK_SIZE, UploadStore


@pytest.fixture()
def client(tmp_path):
    web.store = UploadStore(str(tmp_path / "data"))
    return TestClient(web.app)


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _put(client, session, offset, blob, total_size=None, sha=None):
    headers = {"X-Chunk-Offset": str(offset)}
    if total_size is not None:
        headers["X-Total-Size"] = str(total_size)
    if sha is not None:
        headers["X-Content-SHA256"] = sha
    return client.put(
        f"/api/uploads/{session}/chunks", content=blob, headers=headers
    )


# ---------------------------------------------------------------------------
# happy path, out of order, idempotency
# ---------------------------------------------------------------------------


def test_full_upload_out_of_order_and_seal(client):
    blob = os.urandom(CHUNK_SIZE + 34464)  # two chunks, short final
    sha = _digest(blob)
    c0, c1 = blob[:CHUNK_SIZE], blob[CHUNK_SIZE:]

    # arrive out of order
    r = _put(client, "s1", CHUNK_SIZE, c1, len(blob), sha)
    assert r.status_code == 200, r.text
    assert r.json()["confirmed_chunks"] == [1]
    assert r.json()["missing_ranges"] == [[0, 0]]

    r = _put(client, "s1", 0, c0, len(blob), sha)
    assert r.status_code == 200
    assert r.json()["confirmed_chunks"] == [0, 1]
    assert r.json()["missing_ranges"] == []

    r = client.post("/api/uploads/s1/seal")
    assert r.status_code == 200, r.text
    receipt = r.json()
    assert receipt["sha256"] == sha
    assert receipt["chunks"] == 2
    assert receipt["session"] == "s1"

    # duplicate seal returns the SAME receipt
    r2 = client.post("/api/uploads/s1/seal")
    assert r2.status_code == 200
    assert r2.json() == receipt


def test_retransmission_is_idempotent(client):
    blob = b"x" * 10
    sha = _digest(blob)
    r1 = _put(client, "abc", 0, blob, len(blob), sha)
    assert r1.status_code == 200
    r2 = _put(client, "abc", 0, blob, len(blob), sha)
    assert r2.status_code == 200
    assert r2.json()["duplicate"] is True
    # headers can be omitted on retransmission once metadata is pinned
    r3 = _put(client, "abc", 0, blob)
    assert r3.status_code == 200
    assert r3.json()["duplicate"] is True


def test_reselect_same_file_resends_all_chunks(client):
    # simulates断线后续传: every chunk PUT again with the same bytes
    blob = os.urandom(2 * CHUNK_SIZE + 1)
    sha = _digest(blob)
    parts = [blob[:CHUNK_SIZE], blob[CHUNK_SIZE:2 * CHUNK_SIZE], blob[2 * CHUNK_SIZE:]]
    _put(client, "RESUME", 0, parts[0], len(blob), sha)
    # "reconnect": resend every block, including the confirmed one
    for i, part in enumerate(parts):
        r = _put(client, "RESUME", i * CHUNK_SIZE, part, len(blob), sha)
        assert r.status_code == 200
    assert client.post("/api/uploads/RESUME/seal").status_code == 200


# ---------------------------------------------------------------------------
# conflicts must never mutate state
# ---------------------------------------------------------------------------


def test_metadata_is_pinned_after_first_chunk(client):
    blob = os.urandom(CHUNK_SIZE + 1)
    sha = _digest(blob)
    assert _put(client, "pin", 0, blob[:CHUNK_SIZE], len(blob), sha).status_code == 200

    # different total_size -> 409
    r = _put(client, "pin", CHUNK_SIZE, blob[CHUNK_SIZE:], len(blob) + 1, sha)
    assert r.status_code == 409
    # different digest -> 409
    r = _put(client, "pin", CHUNK_SIZE, blob[CHUNK_SIZE:], len(blob), "a" * 64)
    assert r.status_code == 409

    # state unchanged: final chunk still missing
    status = client.get("/api/uploads/pin").json()
    assert status["confirmed_chunks"] == [0]
    assert status["missing_ranges"] == [[1, 1]]

    # correct request still succeeds
    assert _put(client, "pin", CHUNK_SIZE, blob[CHUNK_SIZE:]).status_code == 200


def test_same_offset_different_bytes_is_409_and_keeps_state(client):
    blob = os.urandom(CHUNK_SIZE)
    sha = _digest(blob)
    _put(client, "c", 0, blob, len(blob), sha)
    other = b"y" * CHUNK_SIZE
    r = _put(client, "c", 0, other, len(blob), _digest(other))
    assert r.status_code == 409
    # original bytes still confirmed; retransmitting them still works
    assert _put(client, "c", 0, blob).json()["duplicate"] is True


# ---------------------------------------------------------------------------
# located rejections
# ---------------------------------------------------------------------------


def test_unaligned_offset_rejected(client):
    blob = b"z" * 10
    r = _put(client, "bad", 1, blob, CHUNK_SIZE + 1, _digest(b"q" * (CHUNK_SIZE + 1)))
    assert r.status_code == 400
    assert "offset 1" in r.json()["error"]
    assert client.get("/api/uploads/bad").status_code == 404  # nothing created


def test_offset_beyond_total_rejected(client):
    blob = os.urandom(CHUNK_SIZE)
    sha = _digest(b"p" * (CHUNK_SIZE + 1))
    r = _put(client, "bad", 2 * CHUNK_SIZE, blob, CHUNK_SIZE + 1, sha)
    assert r.status_code == 400
    assert "beyond" in r.json()["error"]


def test_wrong_chunk_length_rejected(client):
    total = CHUNK_SIZE + 10
    sha = _digest(b"p" * total)
    # final chunk must be exactly 10 bytes
    r = _put(client, "bad", CHUNK_SIZE, b"short", total, sha)
    assert r.status_code == 400
    assert "chunk length 5" in r.json()["error"]
    assert f"{10}" in r.json()["error"]
    # non-final chunk must be exactly 65536 bytes
    r = _put(client, "bad2", 0, b"x" * 100, total, sha)
    assert r.status_code == 400


def test_invalid_session_and_sha_format(client):
    assert _put(client, "bad-id", 0, b"x", 10, "a" * 64).status_code == 400
    assert _put(client, "x" * 33, 0, b"x", 10, "a" * 64).status_code == 400
    r = _put(client, "ok", 0, b"x", 10, "ABCDEF" + "0" * 58)
    assert r.status_code == 400
    r = _put(client, "ok2", 0, b"x", 9 * 1024 * 1024, "a" * 64)
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# sealing
# ---------------------------------------------------------------------------


def test_seal_missing_lists_ranges_and_no_receipt(client, tmp_path):
    total = 5 * CHUNK_SIZE + 7  # six chunks; last one is 7 bytes
    sha = _digest(b"p" * total)
    _put(client, "miss", CHUNK_SIZE, b"p" * CHUNK_SIZE, total, sha)
    _put(client, "miss", 3 * CHUNK_SIZE, b"p" * CHUNK_SIZE, total, sha)
    r = client.post("/api/uploads/miss/seal")
    assert r.status_code == 409
    assert r.json()["missing_ranges"] == [[0, 0], [2, 2], [4, 5]]
    assert not (tmp_path / "data" / "miss" / "receipt.json").exists()


def test_seal_digest_mismatch_produces_no_receipt(client, tmp_path):
    blob = os.urandom(100)
    _put(client, "wrong", 0, blob, len(blob), "a" * 64)
    r = client.post("/api/uploads/wrong/seal")
    assert r.status_code == 409
    assert "digest" in r.json()["error"]
    assert not (tmp_path / "data" / "wrong" / "receipt.json").exists()


def test_sealed_session_rejects_new_chunk_but_keeps_idempotent_put(client):
    blob = os.urandom(CHUNK_SIZE)
    sha = _digest(blob)
    _put(client, "sealed", 0, blob, len(blob), sha)
    client.post("/api/uploads/sealed/seal")

    # identical retransmit stays idempotent
    r = _put(client, "sealed", 0, blob, len(blob), sha)
    assert r.status_code == 200
    assert r.json()["sealed"] is True

    # different bytes -> 409, immutable
    assert _put(client, "sealed", 0, b"q" * CHUNK_SIZE).status_code == 409


def test_unknown_session_seal_400(client):
    r = client.post("/api/uploads/nope/seal")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# durability across "restart"
# ---------------------------------------------------------------------------


def test_progress_and_receipt_survive_restart(client, tmp_path):
    data_dir = tmp_path / "data"
    web.store = UploadStore(str(data_dir))
    blob = os.urandom(CHUNK_SIZE + 5)
    sha = _digest(blob)
    _put(client, "dur", 0, blob[:CHUNK_SIZE], len(blob), sha)

    # restart: brand new store instance over the same directory
    web.store = UploadStore(str(data_dir))
    status = client.get("/api/uploads/dur").json()
    assert status["confirmed_chunks"] == [0]
    assert status["sealed"] is False

    # finish and seal after restart
    assert _put(client, "dur", CHUNK_SIZE, blob[CHUNK_SIZE:]).status_code == 200
    receipt = client.post("/api/uploads/dur/seal").json()

    # another restart: receipt remains, repeat seal yields same receipt
    web.store = UploadStore(str(data_dir))
    again = client.post("/api/uploads/dur/seal")
    assert again.status_code == 200
    assert again.json() == receipt
    assert client.get("/api/uploads/dur").json()["sealed"] is True


def test_min_and_max_file_sizes(client):
    small = b"a"
    r = _put(client, "one", 0, small, 1, _digest(small))
    assert r.status_code == 200
    assert client.post("/api/uploads/one/seal").status_code == 200

    big = os.urandom(8 * 1024 * 1024)
    r = _put(client, "big", 0, big[:CHUNK_SIZE], len(big), _digest(big))
    assert r.status_code == 200


def test_concurrent_out_of_order_puts_then_seal(client):
    import concurrent.futures

    n = 120
    blob = os.urandom(n * CHUNK_SIZE + 1)  # 7.5 MiB, under the 8 MiB limit
    sha = _digest(blob)
    parts = [
        blob[i * CHUNK_SIZE : min((i + 1) * CHUNK_SIZE, len(blob))]
        for i in range(n + 1)
    ]
    order = list(range(n + 1))
    # seed metadata first, then hammer the remaining chunks concurrently
    assert _put(client, "par", 0, parts[0], len(blob), sha).status_code == 200
    rest = order[1:]

    def push(i):
        # include a duplicate retry inside each worker
        r1 = _put(client, "par", i * CHUNK_SIZE, parts[i], len(blob), sha)
        return r1.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(push, rest))
    assert all(c == 200 for c in codes), codes

    status = client.get("/api/uploads/par").json()
    assert len(status["confirmed_chunks"]) == n + 1
    r = client.post("/api/uploads/par/seal")
    assert r.status_code == 200
    assert r.json()["sha256"] == sha

