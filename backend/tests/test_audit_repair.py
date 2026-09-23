"""Integrity audit and original-file repair tests."""

from __future__ import annotations

import hashlib
import json
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


def _sealed_session(client, session="s", n_chunks=3):
    blob = os.urandom(n_chunks * CHUNK_SIZE)
    sha = _digest(blob)
    for i in range(n_chunks):
        part = blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
        _put(client, session, i * CHUNK_SIZE, part, len(blob), sha)
    receipt = client.post(f"/api/uploads/{session}/seal").json()
    return blob, sha, receipt


def _chunk_path(tmp_path, session, i):
    return tmp_path / "data" / session / "chunks" / f"{i:08d}"


def _drop_index(tmp_path, session):
    """Turn a new-style sealed session into a legacy one."""
    os.unlink(tmp_path / "data" / session / "block_index.json")


# ---------------------------------------------------------------------------
# audit gating
# ---------------------------------------------------------------------------


def test_audit_unknown_session_404(client):
    r = client.post("/api/uploads/nope/audit")
    assert r.status_code == 404


def test_audit_rejects_unsealed_without_touching_progress(client, tmp_path):
    blob = b"z" * 100
    sha = _digest(blob)
    _put(client, "open", 0, blob, len(blob), sha)

    r = client.post("/api/uploads/open/audit")
    assert r.status_code == 409
    assert r.json()["reason"] == "not_sealed"

    status = client.get("/api/uploads/open").json()
    assert status["sealed"] is False
    assert status["confirmed_chunks"] == [0]
    assert not (tmp_path / "data" / "open" / "block_index.json").exists()


def test_healthy_sealed_session_audit(client, tmp_path):
    blob, sha, receipt = _sealed_session(client)
    assert (tmp_path / "data" / "s" / "block_index.json").exists()

    r = client.post("/api/uploads/s/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "HEALTHY"
    assert body["block_index"] is True
    assert body["abnormal_ranges"] == []
    assert body["missing_ranges"] == []
    assert body["length_error_ranges"] == []
    assert body["block_digest_error_ranges"] == []
    assert body["unlocatable_digest_mismatch"] is False
    assert body["receipt_sha256"] == sha
    assert body["sealed_at"] == receipt["sealed_at"]


# ---------------------------------------------------------------------------
# legacy sessions: length + whole digest first, then trusted index backfill
# ---------------------------------------------------------------------------


def test_legacy_audit_checks_lengths_and_digest_then_builds_index(
    client, tmp_path
):
    blob, _sha, receipt = _sealed_session(client, "leg")
    _drop_index(tmp_path, "leg")

    r = client.post("/api/uploads/leg/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "HEALTHY"
    assert body["block_index"] is True

    index_path = tmp_path / "data" / "leg" / "block_index.json"
    assert index_path.exists()
    index = json.loads(index_path.read_text())
    assert index["sha256"] == receipt["sha256"]
    assert len(index["blocks"]) == 3
    # receipt stays byte-identical
    assert json.loads((tmp_path / "data" / "leg" / "receipt.json").read_text()) == receipt

    r2 = client.post("/api/uploads/leg/audit")
    assert r2.json()["status"] == "HEALTHY"


def test_legacy_missing_block_is_distinct_from_length_error(client, tmp_path):
    _sealed_session(client, "leg")
    _drop_index(tmp_path, "leg")
    os.unlink(_chunk_path(tmp_path, "leg", 1))

    r = client.post("/api/uploads/leg/audit")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "DEGRADED"
    assert body["missing_ranges"] == [[1, 1]]
    assert body["length_error_ranges"] == []
    assert body["block_digest_error_ranges"] == []
    assert body["abnormal_ranges"] == [[1, 1]]
    assert body["unlocatable_digest_mismatch"] is False
    # failed verification must NOT create a trusted index
    assert not (tmp_path / "data" / "leg" / "block_index.json").exists()


def test_legacy_length_anomaly_is_classified(client, tmp_path):
    _sealed_session(client, "leg")
    _drop_index(tmp_path, "leg")
    p = _chunk_path(tmp_path, "leg", 1)
    p.write_bytes(p.read_bytes()[:-10])  # silent truncation

    r = client.post("/api/uploads/leg/audit")
    body = r.json()
    assert body["status"] == "DEGRADED"
    assert body["length_error_ranges"] == [[1, 1]]
    assert body["missing_ranges"] == []
    assert body["abnormal_ranges"] == [[1, 1]]


def test_legacy_bit_rot_with_right_length_is_unlocatable_mismatch(
    client, tmp_path
):
    _sealed_session(client, "leg")
    _drop_index(tmp_path, "leg")
    p = _chunk_path(tmp_path, "leg", 0)
    raw = bytearray(p.read_bytes())
    raw[3] ^= 0x01  # same length, flipped byte
    p.write_bytes(bytes(raw))

    r = client.post("/api/uploads/leg/audit")
    body = r.json()
    assert body["status"] == "DEGRADED"
    assert body["unlocatable_digest_mismatch"] is True
    assert body["missing_ranges"] == []
    assert body["length_error_ranges"] == []
    assert body["block_digest_error_ranges"] == []
    assert not (tmp_path / "data" / "leg" / "block_index.json").exists()


def test_indexed_session_locates_digest_mismatch_to_block(client, tmp_path):
    _sealed_session(client, "new")
    p = _chunk_path(tmp_path, "new", 2)
    raw = bytearray(p.read_bytes())
    raw[0] ^= 0x01
    p.write_bytes(bytes(raw))

    body = client.post("/api/uploads/new/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["block_digest_error_ranges"] == [[2, 2]]
    assert body["abnormal_ranges"] == [[2, 2]]
    assert body["unlocatable_digest_mismatch"] is False


def test_audit_ranges_can_span_multiple_blocks(client, tmp_path):
    _sealed_session(client, "leg", n_chunks=3)
    _drop_index(tmp_path, "leg")
    os.unlink(_chunk_path(tmp_path, "leg", 0))
    os.unlink(_chunk_path(tmp_path, "leg", 2))
    p = _chunk_path(tmp_path, "leg", 1)
    p.write_bytes(p.read_bytes()[:-3])

    body = client.post("/api/uploads/leg/audit").json()
    assert body["status"] == "DEGRADED"
    assert body["missing_ranges"] == [[0, 0], [2, 2]]
    assert body["length_error_ranges"] == [[1, 1]]
    assert body["abnormal_ranges"] == [[0, 2]]


# ---------------------------------------------------------------------------
# repair
# ---------------------------------------------------------------------------


def test_repair_restores_abnormal_blocks_and_keeps_receipt(client, tmp_path):
    blob, sha, receipt = _sealed_session(client, "fix")
    # damage: one missing block, one bit-rotted block
    os.unlink(_chunk_path(tmp_path, "fix", 0))
    p = _chunk_path(tmp_path, "fix", 2)
    raw = bytearray(p.read_bytes())
    raw[5] ^= 0xFF
    p.write_bytes(bytes(raw))

    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "HEALTHY"
    assert body["repaired_ranges"] == [[0, 0], [2, 2]]
    assert body["receipt_sha256"] == sha
    assert body["sealed_at"] == receipt["sealed_at"]

    # receipt file unchanged; audit now healthy; no repair residue
    after = json.loads((tmp_path / "data" / "fix" / "receipt.json").read_text())
    assert after == receipt
    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"
    assert not (tmp_path / "data" / "fix" / "repair").exists()


def test_repair_wrong_length_is_stable_and_changes_nothing(client, tmp_path):
    blob, _sha, receipt = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 0))

    for payload in (blob[:-1], blob + b"x"):
        r = client.post("/api/uploads/fix/repair", content=payload)
        assert r.status_code == 409
        assert r.json()["reason"] == "length_mismatch"
        assert "repair" not in os.listdir(tmp_path / "data" / "fix")

    # still degraded, same audit result
    audit = client.post("/api/uploads/fix/audit").json()
    assert audit["status"] == "DEGRADED"
    assert audit["missing_ranges"] == [[0, 0]]
    assert (
        json.loads((tmp_path / "data" / "fix" / "receipt.json").read_text())
        == receipt
    )


def test_repair_wrong_digest_is_stable_and_changes_nothing(client, tmp_path):
    blob, _sha, _receipt = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 0))
    wrong = bytearray(blob)
    wrong[0] ^= 0x01  # same length, different content

    r = client.post("/api/uploads/fix/repair", content=bytes(wrong))
    assert r.status_code == 409
    assert r.json()["reason"] == "digest_mismatch"
    assert "repair" not in os.listdir(tmp_path / "data" / "fix")

    # correct file afterwards works
    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200
    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"


def test_duplicate_repair_on_healthy_session_is_idempotent(client, tmp_path):
    blob, _sha, receipt = _sealed_session(client)
    r1 = client.post("/api/uploads/s/repair", content=blob)
    assert r1.status_code == 200
    assert r1.json()["already_healthy"] is True
    assert r1.json()["repaired_ranges"] == []
    r2 = client.post("/api/uploads/s/repair", content=blob)
    assert r2.status_code == 200
    assert r2.json()["already_healthy"] is True
    assert r2.json()["sealed_at"] == receipt["sealed_at"]
    assert not (tmp_path / "data" / "s" / "repair").exists()


def test_repair_unknown_and_unsealed(client):
    assert client.post("/api/uploads/nope/repair", content=b"x").status_code == 404
    blob = b"q" * 50
    _put(client, "open", 0, blob, len(blob), _digest(blob))
    r = client.post("/api/uploads/open/repair", content=blob)
    assert r.status_code == 409
    assert r.json()["reason"] == "not_sealed"


def test_repair_empty_body_rejected(client):
    blob, _sha, _ = _sealed_session(client)
    r = client.post("/api/uploads/s/repair", content=b"")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# interrupted repairs: audit during repair, restart convergence
# ---------------------------------------------------------------------------


def _stage_validated_source(store: UploadStore, session: str, blob: bytes):
    """Simulate a crash after source publication but before chunk fix-up."""
    store._stage_source(session, blob)


def test_audit_while_repair_pending_is_repairing_and_stable(client, tmp_path):
    blob, _sha, _ = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 1))

    store = web.store
    _stage_validated_source(store, "fix", blob)

    r1 = client.post("/api/uploads/fix/audit")
    assert r1.status_code == 200
    assert r1.json()["status"] == "REPAIRING"
    assert r1.json()["missing_ranges"] == [[1, 1]]
    # stable: repeating the audit does not advance or alter the repair
    r2 = client.post("/api/uploads/fix/audit")
    b1, b2 = r1.json(), r2.json()
    b1.pop("checked_at", None)
    b2.pop("checked_at", None)
    assert b2 == b1
    # source still staged; chunk still missing (audit never repairs)
    assert (tmp_path / "data" / "fix" / "repair" / "source").exists()
    assert not _chunk_path(tmp_path, "fix", 1).exists()


def test_wrong_file_while_repair_pending_keeps_staged_source(client, tmp_path):
    blob, _sha, _ = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 1))
    web.store._stage_source("fix", blob)

    wrong = bytearray(blob)
    wrong[0] ^= 0x01
    r = client.post("/api/uploads/fix/repair", content=bytes(wrong))
    assert r.status_code == 409
    assert r.json()["reason"] == "digest_mismatch"
    # the previously validated source survives; audit stays REPAIRING
    assert (tmp_path / "data" / "fix" / "repair" / "source").exists()
    assert client.post("/api/uploads/fix/audit").json()["status"] == "REPAIRING"

    # correct file still converges
    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200 and r.json()["status"] == "HEALTHY"


def test_resume_repair_on_next_request(client, tmp_path):
    blob, _sha, receipt = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 1))
    web.store._stage_source("fix", blob)

    # client retries with the complete original: it converges from the
    # already-staged validated source without needing prior request state
    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200
    assert r.json()["status"] == "HEALTHY"
    assert r.json()["repaired_ranges"] == [[1, 1]]
    assert (
        json.loads((tmp_path / "data" / "fix" / "receipt.json").read_text())
        == receipt
    )


def test_resume_repair_after_service_restart(client, tmp_path):
    blob, _sha, _ = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 0))
    p = _chunk_path(tmp_path, "fix", 2)
    raw = bytearray(p.read_bytes())
    raw[1] ^= 0x01
    p.write_bytes(bytes(raw))
    web.store._stage_source("fix", blob)

    # restart: a brand new store over the same directory resumes at startup
    data_dir = tmp_path / "data"
    web.store = UploadStore(str(data_dir))

    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"
    assert not (tmp_path / "data" / "fix" / "repair").exists()
    # bytes are really back
    rebuilt = b"".join(
        (data_dir / "fix" / "chunks" / f"{i:08d}").read_bytes()
        for i in range(3)
    )
    assert rebuilt == blob


def test_restart_without_staged_source_stays_degraded(client, tmp_path):
    _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 1))
    data_dir = tmp_path / "data"
    web.store = UploadStore(str(data_dir))
    assert client.post("/api/uploads/fix/audit").json()["status"] == "DEGRADED"


# ---------------------------------------------------------------------------
# sealed data can never be rewritten through the chunk interface
# ---------------------------------------------------------------------------


def test_chunk_api_cannot_fill_corrupted_sealed_block(client, tmp_path):
    blob, _sha, _ = _sealed_session(client, "fix")
    os.unlink(_chunk_path(tmp_path, "fix", 0))
    part = blob[:CHUNK_SIZE]
    r = _put(client, "fix", 0, part)
    assert r.status_code == 409
    assert not _chunk_path(tmp_path, "fix", 0).exists()

    p = _chunk_path(tmp_path, "fix", 1)
    raw = bytearray(p.read_bytes())
    raw[0] ^= 0xFF
    p.write_bytes(bytes(raw))
    # even correct original bytes are not accepted through the chunk API
    r = _put(client, "fix", CHUNK_SIZE, blob[CHUNK_SIZE:2 * CHUNK_SIZE])
    assert r.status_code == 409


def test_repair_on_legacy_session_backfills_trusted_index(client, tmp_path):
    blob, _sha, _ = _sealed_session(client, "leg")
    _drop_index(tmp_path, "leg")
    os.unlink(_chunk_path(tmp_path, "leg", 0))

    r = client.post("/api/uploads/leg/repair", content=blob)
    assert r.status_code == 200
    index = json.loads(
        (tmp_path / "data" / "leg" / "block_index.json").read_text()
    )
    assert [b["index"] for b in index["blocks"]] == [0, 1, 2]

    # subsequent rot is now locatable via the new index
    p = _chunk_path(tmp_path, "leg", 1)
    raw = bytearray(p.read_bytes())
    raw[0] ^= 0x01
    p.write_bytes(bytes(raw))
    body = client.post("/api/uploads/leg/audit").json()
    assert body["block_digest_error_ranges"] == [[1, 1]]
