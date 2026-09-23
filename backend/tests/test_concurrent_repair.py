"""Concurrency regression tests for the repair window.

Scenario from the defect report: a sealed two-chunk session loses chunk 0;
the client starts a repair with the complete original file and, while the
repair has begun but the abnormal block is not replaced yet, fires a
concurrent POST .../audit.

The audit must:
  * return PROMPTLY with REPAIRING (never wait for the repair to finish);
  * report the abnormal scope frozen when the repair started;
  * keep that scope stable across repeated audits even as chunks are
    restored one by one (the ranges never drift);
  * converge to HEALTHY once the repair completes, with the original
    receipt (and sealed_at) byte-identical.

Additional regressions covered here:
  * a wrong original file is rejected (409) even while a repair is active
    and changes nothing;
  * duplicate repairs stay idempotent, including concurrent ones;
  * an interrupted repair resumes after a service restart;
  * sealed chunks can never be rewritten through the chunk PUT operation,
    not even while a repair is running.

The repair loop is driven deterministically through a step gate (the
REPAIR_CHUNK_DELAY sleep seam), so no wall-clock timing is involved. A
real in-process uvicorn server exercises the actual HTTP/threadpool path
(async endpoint + run_in_threadpool).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

import httpx
import pytest
import uvicorn

from app import main as web
from app import storage as storage_module
from app.storage import CHUNK_SIZE, UploadStore


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def server(tmp_path):
    """A real uvicorn server (ephemeral port) running in a daemon thread."""
    web.store = UploadStore(str(tmp_path / "data"))
    config = uvicorn.Config(
        web.app, host="127.0.0.1", port=0, log_level="critical"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.01)
    assert server.started, "test uvicorn server never started"
    port = server.servers[0].sockets[0].getsockname()[1]
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=15.0)
    try:
        yield client, tmp_path
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10)


class StepGate:
    """Block the repair loop once per replaced chunk, in deterministic order."""

    def __init__(self, holds: int) -> None:
        self._holds = holds
        self.reached = [threading.Event() for _ in range(holds)]
        self.release = [threading.Event() for _ in range(holds)]
        self._n = 0
        self._lock = threading.Lock()

    def sleep(self, _seconds: float) -> None:
        with self._lock:
            i = self._n
            self._n += 1
        if i < self._holds:
            self.reached[i].set()
            assert self.release[i].wait(timeout=10), f"repair step {i} never released"

    def release_all(self) -> None:
        for event in self.release:
            event.set()


@pytest.fixture()
def gated_repair(monkeypatch):
    def install(gate: StepGate) -> None:
        monkeypatch.setattr(storage_module, "_REPAIR_CHUNK_DELAY", 1.0)
        monkeypatch.setattr(storage_module, "_sleep", gate.sleep)

    return install


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


def _seal(client, session, blob):
    sha = _digest(blob)
    n = (len(blob) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(n):
        part = blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
        r = _put(client, session, i * CHUNK_SIZE, part, len(blob), sha)
        assert r.status_code == 200, r.text
    r = client.post(f"/api/uploads/{session}/seal")
    assert r.status_code == 200, r.text
    return r.json()


def _chunk_path(tmp_path, session, i):
    return tmp_path / "data" / session / "chunks" / f"{i:08d}"


def _repair_async(client, session, blob):
    holder: dict = {}

    def run():
        try:
            holder["response"] = client.post(
                f"/api/uploads/{session}/repair",
                content=blob,
                timeout=httpx.Timeout(30.0),
            )
        except Exception as exc:  # captured, never swallowed silently
            holder["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, holder


def _stable(body: dict) -> dict:
    """Fields that must be identical across same-repair-window audits."""
    return {
        k: v
        for k, v in body.items()
        if k not in ("checked_at",)
    }


# ---------------------------------------------------------------------------
# main scenario: prompt, stable REPAIRING; then HEALTHY; receipt untouched
# ---------------------------------------------------------------------------


def test_concurrent_audit_during_repair_is_prompt_and_stable(
    server, gated_repair
):
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE)
    receipt = _seal(client, "fix", blob)
    os.unlink(_chunk_path(tmp_path, "fix", 0))

    gate = StepGate(holds=1)
    gated_repair(gate)

    thread, holder = _repair_async(client, "fix", blob)
    assert gate.reached[0].wait(timeout=10), "repair never replaced the block"

    # The repair has started and is paused inside its replacement loop; the
    # marker directory must be on disk and the repair request still pending.
    assert (tmp_path / "data" / "fix" / "repair" / "source").exists()
    assert (tmp_path / "data" / "fix" / "repair" / "plan.json").exists()
    assert thread.is_alive()

    # Concurrent audit must come back promptly (old implementation blocked
    # here until the repair finished) with the frozen start-of-repair scope.
    reports = []
    for _ in range(3):
        started = time.monotonic()
        r = client.post("/api/uploads/fix/audit", timeout=3.0)
        assert time.monotonic() - started < 2.0, "audit blocked behind the repair"
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "REPAIRING", body
        assert body["missing_ranges"] == [[0, 0]]
        assert body["abnormal_ranges"] == [[0, 0]]
        assert body["repaired_ranges"] == []
        assert body["receipt_sha256"] == receipt["sha256"]
        assert body["sealed_at"] == receipt["sealed_at"]
        assert body.get("repair_started_at")
        reports.append(_stable(body))

    # Repeated audits within the same repair window must not drift.
    assert reports[0] == reports[1] == reports[2]

    # Audit never repairs: let the repair finish and check its own report.
    gate.release_all()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert "error" not in holder, holder["error"]
    done = holder["response"].json()
    assert holder["response"].status_code == 200
    assert done["status"] == "HEALTHY"
    assert done["repaired_ranges"] == [[0, 0]]
    assert done["sealed_at"] == receipt["sealed_at"]

    # Post-repair audits converge to HEALTHY; the receipt file is unchanged.
    after = client.post("/api/uploads/fix/audit").json()
    assert after["status"] == "HEALTHY"
    assert after["abnormal_ranges"] == []
    assert after["sealed_at"] == receipt["sealed_at"]
    on_disk = json.loads(
        (tmp_path / "data" / "fix" / "receipt.json").read_text()
    )
    assert on_disk == receipt
    assert not (tmp_path / "data" / "fix" / "repair").exists()
    # bytes are really back
    rebuilt = b"".join(
        (_chunk_path(tmp_path, "fix", i)).read_bytes() for i in range(2)
    )
    assert rebuilt == blob


def test_repairing_scope_does_not_drift_while_chunks_are_restored(
    server, gated_repair
):
    """With two abnormal blocks, the frozen scope survives both step-by-step
    restoration and the moment every block is physically back but the repair
    has not finalized yet."""
    client, tmp_path = server
    blob = os.urandom(3 * CHUNK_SIZE)
    receipt = _seal(client, "fix", blob)
    os.unlink(_chunk_path(tmp_path, "fix", 0))
    p2 = _chunk_path(tmp_path, "fix", 2)
    rotten = bytearray(p2.read_bytes())
    rotten[9] ^= 0x55
    p2.write_bytes(bytes(rotten))

    gate = StepGate(holds=2)
    gated_repair(gate)
    thread, holder = _repair_async(client, "fix", blob)

    # Step 1: block 0 restored, block 2 still bit-rotted on disk.
    assert gate.reached[0].wait(timeout=10)
    body1 = client.post("/api/uploads/fix/audit", timeout=3.0).json()
    assert body1["status"] == "REPAIRING"
    assert body1["missing_ranges"] == [[0, 0]]
    assert body1["block_digest_error_ranges"] == [[2, 2]]
    assert body1["abnormal_ranges"] == [[0, 0], [2, 2]]
    # ... and the not-yet-restored block is genuinely still damaged; audit
    # itself must not have repaired anything.
    assert p2.read_bytes() == bytes(rotten)

    gate.release[0].set()

    # Step 2: every block is physically restored, but the repair marker is
    # still present because the repair request has not finalized.
    assert gate.reached[1].wait(timeout=10)
    body2 = client.post("/api/uploads/fix/audit", timeout=3.0).json()
    assert body2["status"] == "REPAIRING"
    # The frozen start-of-repair scope is reported unchanged: no drift even
    # though all chunks are already readable again.
    assert _stable(body2) == _stable(body1)

    gate.release[1].set()
    thread.join(timeout=10)
    assert holder["response"].status_code == 200, holder
    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"
    assert (
        json.loads((tmp_path / "data" / "fix" / "receipt.json").read_text())
        == receipt
    )


# ---------------------------------------------------------------------------
# wrong file during an active repair
# ---------------------------------------------------------------------------


def test_wrong_file_rejected_during_active_repair_and_changes_nothing(
    server, gated_repair
):
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE + 17)
    _seal(client, "fix", blob)
    os.unlink(_chunk_path(tmp_path, "fix", 0))

    gate = StepGate(holds=1)
    gated_repair(gate)
    thread, holder = _repair_async(client, "fix", blob)
    assert gate.reached[0].wait(timeout=10)

    # Wrong length: rejected promptly without queuing behind the repair.
    r = client.post("/api/uploads/fix/repair", content=blob[:-1], timeout=3.0)
    assert r.status_code == 409
    assert r.json()["reason"] == "length_mismatch"

    # Same length, wrong digest.
    wrong = bytearray(blob)
    wrong[0] ^= 0x01
    r = client.post("/api/uploads/fix/repair", content=bytes(wrong), timeout=3.0)
    assert r.status_code == 409
    assert r.json()["reason"] == "digest_mismatch"

    # The in-flight repair and its frozen scope are undisturbed.
    body = client.post("/api/uploads/fix/audit", timeout=3.0).json()
    assert body["status"] == "REPAIRING"
    assert body["missing_ranges"] == [[0, 0]]

    gate.release_all()
    thread.join(timeout=10)
    assert holder["response"].status_code == 200
    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"


# ---------------------------------------------------------------------------
# duplicate / concurrent repair idempotency
# ---------------------------------------------------------------------------


def test_concurrent_duplicate_repair_converges_once_and_is_idempotent(
    server, gated_repair
):
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE)
    receipt = _seal(client, "fix", blob)
    os.unlink(_chunk_path(tmp_path, "fix", 0))

    gate = StepGate(holds=1)
    gated_repair(gate)
    t1, h1 = _repair_async(client, "fix", blob)
    assert gate.reached[0].wait(timeout=10)

    # A second, identical repair races the first: it serializes on the
    # per-session repair lock, then finds a healthy session and must not
    # replace anything a second time.
    t2, h2 = _repair_async(client, "fix", blob)
    time.sleep(0.2)
    assert t2.is_alive()  # queued behind the active repair

    gate.release_all()
    t1.join(timeout=10)
    t2.join(timeout=10)
    first, second = h1["response"].json(), h2["response"].json()
    assert first["status"] == second["status"] == "HEALTHY"
    assert first["repaired_ranges"] == [[0, 0]]
    assert second["repaired_ranges"] == []
    assert second["already_healthy"] is True
    assert second["sealed_at"] == receipt["sealed_at"]

    # Another repair on the now-healthy session stays idempotent.
    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200
    assert r.json()["already_healthy"] is True
    assert not (tmp_path / "data" / "fix" / "repair").exists()


# ---------------------------------------------------------------------------
# sealed chunks stay immutable through the PUT API, even mid-repair
# ---------------------------------------------------------------------------


def test_sealed_chunk_cannot_be_rewritten_during_repair(server, gated_repair):
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE)
    _seal(client, "fix", blob)
    os.unlink(_chunk_path(tmp_path, "fix", 0))

    gate = StepGate(holds=1)
    gated_repair(gate)
    thread, holder = _repair_async(client, "fix", blob)
    assert gate.reached[0].wait(timeout=10)

    # The repair restored chunk 0; trying to overwrite it with different
    # bytes through the chunk API must be rejected.
    evil = bytes(CHUNK_SIZE)
    r = _put(client, "fix", 0, evil)
    assert r.status_code == 409, r.text
    # The repaired (correct) bytes survive the attempt.
    assert _chunk_path(tmp_path, "fix", 0).read_bytes() == blob[:CHUNK_SIZE]

    gate.release_all()
    thread.join(timeout=10)
    assert holder["response"].status_code == 200


# ---------------------------------------------------------------------------
# interruption + restart resume the existing recovery
# ---------------------------------------------------------------------------


def test_interrupted_repair_resumes_after_restart_with_stable_marker(tmp_path):
    blob = os.urandom(3 * CHUNK_SIZE)
    data_dir = tmp_path / "data"
    store = UploadStore(str(data_dir))
    web.store = store

    # Build + seal through the storage layer directly.
    sha = _digest(blob)
    for i in range(3):
        store.put_chunk(
            "fix", i * CHUNK_SIZE,
            blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE],
            len(blob), sha,
        )
    receipt, ok, missing = store.seal("fix")
    assert ok and missing is None

    os.unlink(_chunk_path(tmp_path, "fix", 0))
    p2 = _chunk_path(tmp_path, "fix", 2)
    raw = bytearray(p2.read_bytes())
    raw[2] ^= 0x01
    p2.write_bytes(bytes(raw))

    # Crash shape: validated source + frozen plan published, only block 0
    # restored before the process died.
    store._stage_source("fix", blob)
    result, _ = store._classify(
        "fix", store.get_metadata("fix"), store._read_receipt("fix")
    )
    store._write_plan("fix", store._plan_payload(result))
    _chunk_path(tmp_path, "fix", 0).write_bytes(blob[:CHUNK_SIZE])

    # Restart: a brand new store over the same directory resumes at startup.
    web.store = UploadStore(str(data_dir))
    assert not (data_dir / "fix" / "repair").exists()
    audit = web.store.audit("fix")
    assert audit["status"] == "HEALTHY"
    rebuilt = b"".join(
        (data_dir / "fix" / "chunks" / f"{i:08d}").read_bytes()
        for i in range(3)
    )
    assert rebuilt == blob
    assert (
        json.loads((data_dir / "fix" / "receipt.json").read_text()) == receipt
    )


def test_repairing_stable_for_legacy_session_without_block_index(
    server, gated_repair
):
    """A legacy sealed session (no trusted index) with a missing block also
    gets a frozen plan; concurrent REPAIRING reports are stable and the
    index is (re)built from the validated original when the repair ends."""
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE)
    receipt = _seal(client, "leg", blob)
    os.unlink(tmp_path / "data" / "leg" / "block_index.json")
    os.unlink(_chunk_path(tmp_path, "leg", 1))

    gate = StepGate(holds=1)
    gated_repair(gate)
    thread, holder = _repair_async(client, "leg", blob)
    assert gate.reached[0].wait(timeout=10)

    bodies = []
    for _ in range(2):
        body = client.post("/api/uploads/leg/audit", timeout=3.0).json()
        assert body["status"] == "REPAIRING", body
        assert body["missing_ranges"] == [[1, 1]]
        assert body["abnormal_ranges"] == [[1, 1]]
        bodies.append(_stable(body))
    assert bodies[0] == bodies[1]

    gate.release_all()
    thread.join(timeout=10)
    assert holder["response"].status_code == 200
    after = client.post("/api/uploads/leg/audit").json()
    assert after["status"] == "HEALTHY" and after["block_index"] is True
    assert after["sealed_at"] == receipt["sealed_at"]
    index = json.loads(
        (tmp_path / "data" / "leg" / "block_index.json").read_text()
    )
    assert [b["index"] for b in index["blocks"]] == [0, 1]


def test_audit_during_teardown_reports_converged_state_not_empty_repairing(
    tmp_path,
):
    """Final-teardown window: the repair thread still holds the session
    lock but source (and plan) are already unlinked and chunks are restored.
    A concurrent audit must report the converged HEALTHY state, never an
    empty REPAIRING."""
    blob = os.urandom(2 * CHUNK_SIZE)
    store = UploadStore(str(tmp_path / "data"))
    web.store = store
    sha = _digest(blob)
    for i in range(2):
        store.put_chunk(
            "fix", i * CHUNK_SIZE,
            blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE],
            len(blob), sha,
        )
    store.seal("fix")

    lock = store._repair_locks.setdefault("fix", threading.Lock())
    acquired = lock.acquire()  # stand in for the repairing thread
    assert acquired
    try:
        holder: dict = {}

        def audit():
            holder["body"] = store.audit("fix")

        t = threading.Thread(target=audit, daemon=True)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive(), "audit blocked behind the repair lock"
        body = holder["body"]
        assert body["status"] == "HEALTHY", body
        assert body["abnormal_ranges"] == []
    finally:
        lock.release()


def test_audit_in_source_before_plan_window_reports_live_scope(tmp_path):
    """Start window: the repairing thread holds the lock, source is staged
    but plan.json is not frozen yet (no chunk has been replaced). Audit
    answers promptly from the live classification as REPAIRING."""
    blob = os.urandom(2 * CHUNK_SIZE)
    store = UploadStore(str(tmp_path / "data"))
    web.store = store
    sha = _digest(blob)
    for i in range(2):
        store.put_chunk(
            "fix", i * CHUNK_SIZE,
            blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE],
            len(blob), sha,
        )
    store.seal("fix")
    os.unlink(_chunk_path(tmp_path, "fix", 1))

    lock = store._repair_locks.setdefault("fix", threading.Lock())
    with lock:
        store._stage_source("fix", blob)  # source present, plan.json absent
        holder: dict = {}

        def audit():
            holder["body"] = store.audit("fix")

        t = threading.Thread(target=audit, daemon=True)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive(), "audit blocked behind the repair lock"
        body = holder["body"]
        assert body["status"] == "REPAIRING", body
        assert body["missing_ranges"] == [[1, 1]]
        assert body["abnormal_ranges"] == [[1, 1]]


def test_orphaned_plan_without_source_is_discarded(server):
    """Crash after source unlink but before plan unlink: the stale scope
    snapshot must never leak into a later repair or audit."""
    client, tmp_path = server
    blob = os.urandom(2 * CHUNK_SIZE)
    receipt = _seal(client, "fix", blob)

    repair_dir = tmp_path / "data" / "fix" / "repair"
    repair_dir.mkdir()
    (repair_dir / "plan.json").write_text(json.dumps({
        "version": 1,
        "missing_ranges": [[0, 0]],
        "length_error_ranges": [],
        "block_digest_error_ranges": [],
        "abnormal_ranges": [[0, 0]],
        "unlocatable_digest_mismatch": False,
        "block_index": True,
        "started_at": "2020-01-01T00:00:00Z",
    }))

    # No source: the session is simply HEALTHY; the orphan is ignored.
    body = client.post("/api/uploads/fix/audit").json()
    assert body["status"] == "HEALTHY"

    # A fresh (idempotent) repair must not resurrect the stale plan.
    r = client.post("/api/uploads/fix/repair", content=blob)
    assert r.status_code == 200 and r.json()["already_healthy"] is True
    assert not repair_dir.exists()
    assert client.post("/api/uploads/fix/audit").json()["status"] == "HEALTHY"
    assert (
        json.loads((tmp_path / "data" / "fix" / "receipt.json").read_text())
        == receipt
    )


def test_legacy_marker_without_plan_still_repairs_on_restart(tmp_path):
    """A marker left by an older version (source present, no plan.json) is
    frozen on resume and still converges."""
    blob = os.urandom(2 * CHUNK_SIZE)
    data_dir = tmp_path / "data"
    store = UploadStore(str(data_dir))
    sha = _digest(blob)
    for i in range(2):
        store.put_chunk(
            "fix", i * CHUNK_SIZE,
            blob[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE],
            len(blob), sha,
        )
    receipt, ok, _ = store.seal("fix")
    assert ok
    os.unlink(_chunk_path(tmp_path, "fix", 1))
    store._stage_source("fix", blob)  # no plan.json: old-version crash shape

    web.store = UploadStore(str(data_dir))
    assert web.store.audit("fix")["status"] == "HEALTHY"
    assert not (data_dir / "fix" / "repair").exists()
    assert (
        json.loads((data_dir / "fix" / "receipt.json").read_text()) == receipt
    )
