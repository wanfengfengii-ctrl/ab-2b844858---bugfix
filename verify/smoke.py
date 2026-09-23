"""HTTP smoke test for a running sealing-desk instance.

Exercises the whole contract over real HTTP (stdlib only):
  health + SPA, validation, out-of-order PUT, idempotent retransmission,
  409 conflicts that never mutate state, missing-range listing, atomic seal,
  identical receipt on repeated seal, and sealed-session immutability.
  Then: sealed-session integrity audit (HEALTHY), unsealed audit rejection,
  wrong-file / duplicate repair stability, and repair gating.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
CHUNK = 65536


def call(method: str, path: str, body: bytes | None = None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode(errors="replace")}


def put(session, offset, data, total=None, sha=None):
    headers = {"X-Chunk-Offset": str(offset), "Content-Type": "application/octet-stream"}
    if total is not None:
        headers["X-Total-Size"] = str(total)
    if sha is not None:
        headers["X-Content-SHA256"] = sha
    return call("PUT", f"/api/uploads/{session}/chunks", data, headers)


def wait_healthy(timeout=30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _ = call("GET", "/health")
            if status == 200:
                return
        except Exception as exc:  # connection refused while starting
            last = exc
        time.sleep(0.5)
    raise SystemExit(f"service never became healthy: {last}")


def check(cond, label):
    if not cond:
        raise SystemExit(f"SMOKE FAIL: {label}")
    print(f"  ok - {label}")


def main():
    wait_healthy()
    suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    s = f"SMOKE{suffix}"

    print("[health + static]")
    status, body = call("GET", "/health")
    check(status == 200 and body.get("status") == "ok", "GET /health -> 200 ok")
    req = urllib.request.Request(BASE + "/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        index = resp.read().decode()
    check(resp.status == 200 and 'id="root"' in index, "SPA index.html is served")

    print("[validation]")
    status, body = put("bad-id!", 0, b"x", 1, "a" * 64)
    check(status == 400, f"invalid session rejected (400), got {status}")
    bad_digest = put(s + "B", 0, b"x", 1, "Z" * 64)
    check(bad_digest[0] == 400, "uppercase digest rejected (400)")

    # 3-chunk file, last chunk short
    blob = os.urandom(2 * CHUNK + 123)
    digest = hashlib.sha256(blob).hexdigest()
    c0, c1, c2 = blob[:CHUNK], blob[CHUNK:2 * CHUNK], blob[2 * CHUNK:]

    print("[out of order arrival]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["confirmed_chunks"] == [1], "chunk #1 first -> 200")
    status, body = put(s, 2 * CHUNK, c2)
    check(status == 200 and set(body["confirmed_chunks"]) == {1, 2}, "chunk #2 -> 200")

    print("[located rejections before completion]")
    status, body = put(s, 1, b"x")
    check(status == 400 and "not aligned" in body["error"], "unaligned offset -> 400")
    status, body = put(s, 3 * CHUNK, b"x")
    check(status == 400 and "beyond" in body["error"], "out-of-bounds offset -> 400")
    status, body = put(s, 0, c0[:-1])
    check(status == 400 and "chunk length" in body["error"], "wrong chunk length -> 400")

    print("[seal with missing blocks]")
    status, body = call("POST", f"/api/uploads/{s}/seal")
    check(status == 409 and body["missing_ranges"] == [[0, 0]],
          f"missing ranges reported: {body}")

    print("[idempotent retransmission then completion]")
    status, body = put(s, CHUNK, c1, len(blob), digest)
    check(status == 200 and body["duplicate"] is True, "identical retransmit -> 200 duplicate")
    status, body = put(s, 0, c0)
    check(status == 200 and body["confirmed_chunks"] == [0, 1, 2], "chunk #0 completes upload")

    print("[409 conflict must not overwrite]")
    evil = bytearray(c1)
    evil[0] ^= 0xFF
    status, body = put(s, CHUNK, bytes(evil))
    check(status == 409, f"different bytes at same offset -> 409, got {status} {body}")
    status, body = put(s, CHUNK, c1)
    check(status == 200 and body["duplicate"] is True,
          "original chunk still intact and idempotent after 409")
    status, body = put(s, CHUNK, c1, len(blob) + 1, digest)
    check(status == 409, "changed total_size -> 409")
    status, body = put(s, CHUNK, c1, len(blob), "a" * 64)
    check(status == 409, "changed sha256 -> 409")

    print("[atomic seal + stable receipt]")
    status, receipt = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and receipt["sha256"] == digest and receipt["chunks"] == 3,
          f"seal succeeds with correct digest: {receipt}")
    status, again = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and again == receipt, "repeat seal returns the SAME receipt")

    print("[sealed immutability]")
    wrong0 = bytes(CHUNK)  # all-zero chunk, differs from random c0
    status, _ = put(s, 0, wrong0)
    check(status == 409, "different chunk after seal -> 409")
    status, body = put(s, 0, c0)
    check(status == 200 and body["sealed"] is True, "identical PUT after seal stays 200")

    print("[digest mismatch never seals]")
    bad = b"q" * 50
    sb = s + "D"
    status, _ = put(sb, 0, bad, len(bad), "a" * 64)
    check(status == 200, "wrong-declared digest upload accepted chunk-wise")
    status, body = call("POST", f"/api/uploads/{sb}/seal")
    check(status == 409 and "digest" in body["error"], "digest mismatch -> 409, no receipt")
    status, body = call("GET", f"/api/uploads/{sb}")
    check(status == 200 and body["sealed"] is False and body["receipt"] is None,
          "no receipt exists after digest mismatch")

    print("[integrity audit gating]")
    status, body = call("POST", f"/api/uploads/ghost/audit")
    check(status == 404, "audit of unknown session -> 404")
    status, body = call("POST", f"/api/uploads/{sb}/audit")
    check(status == 409 and body.get("reason") == "not_sealed",
          "audit of unsealed session -> 409 not_sealed")
    status, before = call("GET", f"/api/uploads/{sb}")
    status, _ = call("POST", f"/api/uploads/{sb}/audit")
    status, after = call("GET", f"/api/uploads/{sb}")
    check(before == after, "audit never changes unsealed upload progress")

    print("[healthy audit + persistent block index]")
    status, body = call("POST", f"/api/uploads/{s}/audit")
    check(status == 200 and body["status"] == "HEALTHY", f"sealed session audit HEALTHY: {body}")
    check(body["block_index"] is True, "new session carries a trusted per-block index")
    check(body["abnormal_ranges"] == [] and body["missing_ranges"] == [],
          "no abnormal ranges on healthy session")
    check(body["receipt_sha256"] == digest and body["sealed_at"] == receipt["sealed_at"],
          "audit report references the unchanged receipt")
    status, again = call("POST", f"/api/uploads/{s}/audit")
    check(status == 200 and again["status"] == "HEALTHY", "repeat audit stays HEALTHY")

    print("[repair gating: wrong files and stable results]")
    status, _ = call("POST", f"/api/uploads/{s}/repair", body=b"")
    check(status == 400, "empty repair body -> 400")
    status, body = call("POST", f"/api/uploads/ghost/repair", body=b"x")
    check(status == 404, "repair of unknown session -> 404")
    status, body = call("POST", f"/api/uploads/{sb}/repair", body=bad)
    check(status == 409 and body.get("reason") == "not_sealed",
          "repair of unsealed session -> 409 not_sealed")

    status, body = call("POST", f"/api/uploads/{s}/repair", body=blob[:-1])
    check(status == 409 and body.get("reason") == "length_mismatch",
          f"repair with short file -> 409 length_mismatch: {body}")
    status, body = call("POST", f"/api/uploads/{s}/repair", body=blob + b"x")
    check(status == 409 and body.get("reason") == "length_mismatch",
          "repair with long file -> 409 length_mismatch")
    wrong = bytearray(blob)
    wrong[7] ^= 0x01
    status, body = call("POST", f"/api/uploads/{s}/repair", body=bytes(wrong))
    check(status == 409 and body.get("reason") == "digest_mismatch",
          "repair with same-length wrong digest -> 409 digest_mismatch")

    print("[audit stable after rejected repairs; receipt untouched]")
    status, body = call("POST", f"/api/uploads/{s}/audit")
    check(status == 200 and body["status"] == "HEALTHY",
          "rejected repairs leave the session HEALTHY")
    status, still = call("POST", f"/api/uploads/{s}/seal")
    check(status == 200 and still == receipt, "receipt identical after repair attempts")

    print("[duplicate repair on healthy session is idempotent]")
    status, body = call("POST", f"/api/uploads/{s}/repair", body=blob)
    check(status == 200 and body["status"] == "HEALTHY"
          and body.get("already_healthy") is True
          and body["repaired_ranges"] == [],
          f"repair of healthy session -> 200 already_healthy: {body}")
    status, body2 = call("POST", f"/api/uploads/{s}/repair", body=blob)
    stable_fields = {k: v for k, v in body.items() if k != "completed_at"}
    stable_fields2 = {k: v for k, v in body2.items() if k != "completed_at"}
    check(status == 200 and stable_fields2 == stable_fields,
          "duplicate repair returns a stable result")
    check(body2["sealed_at"] == receipt["sealed_at"], "sealed_at never changes")

    print("[chunk API still cannot rewrite sealed data]")
    status, _ = put(s, 0, bytes(CHUNK))
    check(status == 409, "sealed chunk rewrite via PUT -> 409")
    status, body = call("POST", f"/api/uploads/{s}/audit")
    check(body["status"] == "HEALTHY", "session remains HEALTHY")

    print(f"\nSMOKE OK against {BASE} (sessions {s}, {sb})")


if __name__ == "__main__":
    main()
