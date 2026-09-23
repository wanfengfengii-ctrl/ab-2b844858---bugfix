"""File-backed, crash-safe persistence for upload sessions.

Each session lives in a single directory holding:
  meta.json       – immutable metadata, written atomically with fsync
  chunks/NNNN     – one file per confirmed chunk (raw bytes), atomically renamed
  receipt.json    – present only after a successful atomic seal
  block_index.json – trusted per-chunk SHA-256 index, written together with
                     the receipt for new sessions; backfilled on the first
                     successful audit of a legacy (pre-index) session
  repair/         – present only while an original-file repair is in flight:
    source        – the fully validated original file (length AND whole-file
                    digest match the receipt); its atomic appearance is the
                    persistent commit marker. An interrupted request or a
                    restart resumes from this file.
    plan.json     – the abnormal-block scope frozen at the moment the repair
                    started. Concurrent audits report REPAIRING with exactly
                    this snapshot for the whole repair window, so the ranges
                    never drift while chunks are restored one by one. A marker
                    without a plan (interrupted repairs from older versions)
                    is reported from a live classification instead.

A process-wide threading.RLock serializes short metadata/state transitions;
the potentially long chunk-replacement loop of a repair runs OUTSIDE that
lock under a per-session repair lock, so a concurrent /audit stays
responsive and reports REPAIRING instead of waiting for the repair to
finish. Atomic rename + fsync make the on-disk state crash-consistent, so
progress, receipts and interrupted repairs survive service restarts.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

CHUNK_SIZE = 65536

# Default limits; can be overridden through the environment.
MIN_SESSION_LEN = 1
MAX_SESSION_LEN = 32
MIN_TOTAL_SIZE = 1
MAX_TOTAL_SIZE = 8 * 1024 * 1024

_DIGEST_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_BLOCK_INDEX_VERSION = 1
_BLOCK_INDEX_FILE = "block_index.json"
_REPAIR_DIR = "repair"
_REPAIR_SOURCE = "source"
_REPAIR_PLAN = "plan.json"
_REPAIR_PLAN_VERSION = 1


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


# Seconds to pause after replacing each abnormal chunk during a repair.
# 0 in production (the default); a small positive value (set via the compose
# service env) keeps the observable repair window open long enough for
# concurrent audits to reliably report REPAIRING over real HTTP.
_REPAIR_CHUNK_DELAY = _env_float("REPAIR_CHUNK_DELAY", 0.0)

# Indirection so tests can gate the replacement loop deterministically.
_sleep = time.sleep

# Audit statuses returned over HTTP.
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
REPAIRING = "REPAIRING"


def _is_sha256_hex(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


def _utcnow() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


@dataclass
class Metadata:
    total_size: int
    sha256: str
    chunk_count: int


@dataclass
class BlockIndex:
    total_size: int
    sha256: str
    chunk_count: int
    blocks: list[dict]  # [{"index", "size", "sha256"}, ...]


@dataclass
class _Classification:
    """Outcome of reading and checking every sealed chunk."""

    missing: set[int] = field(default_factory=set)
    bad_length: set[int] = field(default_factory=set)
    bad_digest: set[int] = field(default_factory=set)
    # Whole-file digest mismatch that cannot be attributed to a concrete
    # block: only possible for legacy sessions without a trusted per-chunk
    # index (or if the index itself is corrupt).
    unlocatable_digest_mismatch: bool = False
    index_present: bool = False

    def abnormal(self) -> set[int]:
        return self.missing | self.bad_length | self.bad_digest

    def is_clean(self) -> bool:
        return not self.abnormal() and not self.unlocatable_digest_mismatch


def _validate_session(session: str) -> str:
    if not MIN_SESSION_LEN <= len(session) <= MAX_SESSION_LEN:
        raise RejectError("session id must be 1-32 characters long")
    if not session.isascii() or not session.isalnum():
        raise RejectError("session id must contain only ASCII letters and digits")
    return session


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _read_json(path: str) -> dict:
    with open(path, "rb") as fh:
        return json.loads(fh.read())


def _ranges(indices: set[int]) -> list[list[int]]:
    """Compress a sorted index set into closed [start, end] ranges."""
    out: list[list[int]] = []
    start: Optional[int] = None
    prev: Optional[int] = None
    for i in sorted(indices):
        if start is None:
            start = prev = i
        elif i == prev + 1:
            prev = i
        else:
            out.append([start, prev])
            start = prev = i
    if start is not None:
        out.append([start, prev])
    return out


def _missing_ranges(present: set[int], chunk_count: int) -> list[list[int]]:
    return _ranges(set(range(chunk_count)) - present)


class ConflictError(Exception):
    """Content/metadata of an idempotent retransmission does not match."""

    def __init__(self, message: str, reason: Optional[str] = None) -> None:
        super().__init__(message)
        self.reason = reason


class RejectError(Exception):
    """Chunk index/offset/length is malformed (mapped to HTTP 400)."""


class UploadStore:
    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.RLock()
        # Per-session repair locks: the chunk-replacement loop may take a
        # while and runs without holding _lock, while audits stay
        # responsive. Guarded by _lock.
        self._repair_locks: dict[str, threading.Lock] = {}
        # Service restart: continue every interrupted, validated repair so
        # the session converges even without a new client request.
        self._resume_all_repairs()

    # ---- paths -----------------------------------------------------------

    def _dir(self, session: str) -> str:
        return os.path.join(self.root, session)

    def _meta_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "meta.json")

    def _chunks_dir(self, session: str) -> str:
        return os.path.join(self._dir(session), "chunks")

    def _chunk_path(self, session: str, index: int) -> str:
        return os.path.join(self._chunks_dir(session), f"{index:08d}")

    def _receipt_path(self, session: str) -> str:
        return os.path.join(self._dir(session), "receipt.json")

    def _index_path(self, session: str) -> str:
        return os.path.join(self._dir(session), _BLOCK_INDEX_FILE)

    def _repair_dir(self, session: str) -> str:
        return os.path.join(self._dir(session), _REPAIR_DIR)

    def _repair_source_path(self, session: str) -> str:
        return os.path.join(self._repair_dir(session), _REPAIR_SOURCE)

    def _repair_plan_path(self, session: str) -> str:
        return os.path.join(self._repair_dir(session), _REPAIR_PLAN)

    # ---- reads -----------------------------------------------------------

    def get_metadata(self, session: str) -> Optional[Metadata]:
        try:
            raw = _read_json(self._meta_path(session))
        except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None
        return Metadata(
            total_size=int(raw["total_size"]),
            sha256=str(raw["sha256"]),
            chunk_count=int(raw["chunk_count"]),
        )

    def _present_indices(self, session: str, chunk_count: int) -> set[int]:
        present: set[int] = set()
        try:
            names = os.listdir(self._chunks_dir(session))
        except FileNotFoundError:
            return present
        for name in names:
            if len(name) == 8 and name.isdigit():
                idx = int(name)
                if 0 <= idx < chunk_count:
                    present.add(idx)
        return present

    def status(self, session: str) -> Optional[dict]:
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                return None
            present = sorted(self._present_indices(session, meta.chunk_count))
            receipt = self._read_receipt(session)
            return {
                "session": session,
                "total_size": meta.total_size,
                "sha256": meta.sha256,
                "chunk_count": meta.chunk_count,
                "confirmed_chunks": present,
                "missing_ranges": _missing_ranges(set(present), meta.chunk_count),
                "sealed": receipt is not None,
                "receipt": receipt,
            }

    def _read_receipt(self, session: str) -> Optional[dict]:
        try:
            raw = _read_json(self._receipt_path(session))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return raw

    def _load_index(self, session: str, meta: Metadata) -> Optional[BlockIndex]:
        """Load the trusted per-chunk index; a malformed one is ignored,
        which downgrades the session to the legacy verification path."""
        try:
            raw = _read_json(self._index_path(session))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        try:
            if int(raw.get("version")) != _BLOCK_INDEX_VERSION:
                return None
            total_size = int(raw["total_size"])
            chunk_count = int(raw["chunk_count"])
            sha = str(raw["sha256"])
            blocks = list(raw["blocks"])
            if (
                total_size != meta.total_size
                or chunk_count != meta.chunk_count
                or sha != meta.sha256
                or len(blocks) != chunk_count
            ):
                return None
            parsed: list[dict] = []
            for i, entry in enumerate(blocks):
                idx = int(entry["index"])
                size = int(entry["size"])
                digest = str(entry["sha256"])
                if idx != i or size != self._expected_block_size(meta, i):
                    return None
                if not _is_sha256_hex(digest):
                    return None
                parsed.append({"index": idx, "size": size, "sha256": digest})
        except (KeyError, TypeError, ValueError):
            return None
        return BlockIndex(
            total_size=total_size,
            sha256=sha,
            chunk_count=chunk_count,
            blocks=parsed,
        )

    def _write_index(self, session: str, meta: Metadata, blocks: list[dict]) -> None:
        payload = {
            "version": _BLOCK_INDEX_VERSION,
            "total_size": meta.total_size,
            "chunk_size": CHUNK_SIZE,
            "chunk_count": meta.chunk_count,
            "sha256": meta.sha256,
            "blocks": blocks,
        }
        _atomic_write(self._index_path(session), json.dumps(payload, indent=2).encode())

    @staticmethod
    def _expected_block_size(meta: Metadata, index: int) -> int:
        start = index * CHUNK_SIZE
        return min(CHUNK_SIZE, meta.total_size - start)

    # ---- writes ----------------------------------------------------------

    def put_chunk(
        self,
        session: str,
        offset: int,
        data: bytes,
        total_size: Optional[int],
        sha256: Optional[str],
    ) -> dict:
        _validate_session(session)
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise RejectError("offset must be an integer")
        if offset < 0:
            raise RejectError("offset must be >= 0")
        if not isinstance(data, (bytes, bytearray)):
            raise RejectError("chunk payload must be raw bytes")
        data = bytes(data)

        with self._lock:
            existing = self.get_metadata(session)
            if existing is None:
                # Build + validate in memory first; nothing touches disk until
                # every shape check has passed.
                meta = self._build_metadata(total_size, sha256)
            else:
                meta = existing
                if total_size is not None and total_size != meta.total_size:
                    raise ConflictError(
                        f"total_size mismatch: session pinned to {meta.total_size}"
                    )
                if sha256 is not None and sha256 != meta.sha256:
                    raise ConflictError("sha256 mismatch: session digest is pinned")

            if offset % CHUNK_SIZE != 0:
                raise RejectError(f"offset {offset} is not aligned to {CHUNK_SIZE}")
            if offset >= meta.total_size:
                raise RejectError(
                    f"offset {offset} is beyond total_size {meta.total_size}"
                )
            expected_size = self._expected_block_size(meta, offset // CHUNK_SIZE)
            if len(data) != expected_size:
                raise RejectError(
                    f"chunk length {len(data)} at offset {offset} must be {expected_size}"
                )
            index = offset // CHUNK_SIZE

            # All checks passed: pin the metadata on the first valid chunk.
            if existing is None:
                os.makedirs(self._chunks_dir(session), exist_ok=True)
                _atomic_write(
                    self._meta_path(session),
                    json.dumps(
                        {
                            "total_size": meta.total_size,
                            "sha256": meta.sha256,
                            "chunk_count": meta.chunk_count,
                        },
                        indent=2,
                    ).encode(),
                )

            sealed = self._read_receipt(session) is not None
            path = self._chunk_path(session, index)
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    stored = fh.read()
                if stored != data:
                    raise ConflictError(
                        f"chunk at offset {offset} already confirmed with different bytes"
                    )
                duplicate = True
            else:
                # The chunk API is never allowed to (re)write sealed data;
                # corrupted/missing blocks of a sealed session are restored
                # exclusively through /repair with the validated original.
                if sealed:
                    raise ConflictError("session is already sealed; no new chunks accepted")
                _atomic_write(path, data)
                duplicate = False

            present = self._present_indices(session, meta.chunk_count)
            return {
                "session": session,
                "offset": offset,
                "index": index,
                "size": len(data),
                "duplicate": duplicate,
                "confirmed_chunks": sorted(present),
                "chunk_count": meta.chunk_count,
                "missing_ranges": _missing_ranges(present, meta.chunk_count),
                "sealed": sealed,
            }

    def _build_metadata(
        self, total_size: Optional[int], sha256: Optional[str]
    ) -> Metadata:
        if total_size is None or sha256 is None:
            raise RejectError(
                "total_size and sha256 are required for the first chunk of a session"
            )
        if not isinstance(total_size, int) or isinstance(total_size, bool):
            raise RejectError("total_size must be an integer")
        if not MIN_TOTAL_SIZE <= total_size <= MAX_TOTAL_SIZE:
            raise RejectError(
                f"total_size must be between {MIN_TOTAL_SIZE} and {MAX_TOTAL_SIZE} bytes"
            )
        if not isinstance(sha256, str) or not _is_sha256_hex(sha256):
            raise RejectError("sha256 must be 64 lowercase hex characters")

        chunk_count = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        return Metadata(
            total_size=total_size, sha256=sha256, chunk_count=chunk_count
        )

    def seal(self, session: str) -> tuple[dict, bool, Optional[list[list[int]]]]:
        """Return (receipt_or_status, ok, missing_ranges).

        ok=True  -> receipt dict (possibly an identical prior receipt)
        ok=False -> digest mismatch; missing_ranges is None
        missing -> blocks missing; receipt is None and missing_ranges set
        """
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                raise RejectError("unknown session; upload at least one chunk first")

            prior = self._read_receipt(session)
            if prior is not None:
                return prior, True, None

            present = self._present_indices(session, meta.chunk_count)
            missing = _missing_ranges(present, meta.chunk_count)
            if missing:
                return {}, False, missing

            # One pass over the blocks: per-block digests (the trusted index
            # persisted with the receipt) plus the whole-file digest.
            whole = hashlib.sha256()
            block_entries: list[dict] = []
            for i in range(meta.chunk_count):
                with open(self._chunk_path(session, i), "rb") as fh:
                    blob = fh.read()
                whole.update(blob)
                block_entries.append(
                    {
                        "index": i,
                        "size": len(blob),
                        "sha256": hashlib.sha256(blob).hexdigest(),
                    }
                )
            actual = whole.hexdigest()
            if actual != meta.sha256:
                raise ConflictError(
                    f"server digest {actual} does not match declared {meta.sha256}"
                )

            receipt = {
                "receipt_id": _DIGEST_PREFIX + actual,
                "session": session,
                "total_size": meta.total_size,
                "sha256": actual,
                "chunks": meta.chunk_count,
                "chunk_size": CHUNK_SIZE,
                "sealed_at": _utcnow(),
            }
            # Persist the trusted per-chunk index first, then the receipt.
            # A crash in between leaves an unsealed session whose re-seal
            # simply rewrites both files; the receipt's appearance stays the
            # single atomic "sealed" transition.
            self._write_index(session, meta, block_entries)
            _atomic_write(
                self._receipt_path(session), json.dumps(receipt, indent=2).encode()
            )
            return receipt, True, None

    # ---- integrity audit -------------------------------------------------

    def _read_block(self, session: str, index: int) -> Optional[bytes]:
        """Return block bytes, or None when the block is missing/unreadable."""
        try:
            with open(self._chunk_path(session, index), "rb") as fh:
                return fh.read()
        except (FileNotFoundError, IsADirectoryError, OSError):
            return None

    def _classify(
        self, session: str, meta: Metadata, receipt: dict
    ) -> tuple[_Classification, Optional[list[dict]]]:
        """Check every chunk against the trusted index when available.

        Legacy sessions (no index) are checked by block length first; only
        when every block is present with the right length can the whole-file
        digest decide. A legacy success yields trusted-index entries for the
        caller to persist (this method never writes); a legacy digest
        mismatch can only be reported as unlocatable.

        Returns (classification, backfill_entries); backfill_entries is set
        only for a clean legacy session whose index still has to be written.
        Safe to call WITHOUT self._lock: every chunk file appears and is
        replaced atomically, so concurrent readers only ever see complete
        old or new blocks.
        """
        index = self._load_index(session, meta)
        result = _Classification(index_present=index is not None)

        if index is not None:
            for i, entry in enumerate(index.blocks):
                blob = self._read_block(session, i)
                if blob is None:
                    result.missing.add(i)
                elif len(blob) != entry["size"]:
                    result.bad_length.add(i)
                elif hashlib.sha256(blob).hexdigest() != entry["sha256"]:
                    result.bad_digest.add(i)
            # Defence in depth: blocks matching their index must also chain
            # to the receipt's whole-file digest.
            if result.is_clean() and self._whole_digest(session, meta) != receipt["sha256"]:
                result.unlocatable_digest_mismatch = True
            return result, None

        # Legacy path: lengths first, digest only when shape is complete.
        blobs: list[Optional[bytes]] = []
        for i in range(meta.chunk_count):
            blob = self._read_block(session, i)
            blobs.append(blob)
            if blob is None:
                result.missing.add(i)
            elif len(blob) != self._expected_block_size(meta, i):
                result.bad_length.add(i)

        if result.missing or result.bad_length:
            return result, None

        whole = hashlib.sha256()
        entries: list[dict] = []
        for i, blob in enumerate(blobs):
            whole.update(blob)
            entries.append(
                {
                    "index": i,
                    "size": len(blob),
                    "sha256": hashlib.sha256(blob).hexdigest(),
                }
            )
        if whole.hexdigest() != receipt["sha256"]:
            result.unlocatable_digest_mismatch = True
            return result, None

        # Legacy session verified end to end; the caller persists these
        # per-block digests as the trusted index.
        return result, entries

    def _whole_digest(self, session: str, meta: Metadata) -> Optional[str]:
        """Concatenate every chunk in order and hash. None if unreadable."""
        digest = hashlib.sha256()
        for i in range(meta.chunk_count):
            blob = self._read_block(session, i)
            if blob is None:
                return None
            digest.update(blob)
        return digest.hexdigest()

    @staticmethod
    def _audit_payload(
        session: str, result: _Classification, receipt: dict, status: str
    ) -> dict:
        abnormal = result.abnormal()
        return {
            "session": session,
            "status": status,
            "sealed": True,
            "block_index": result.index_present,
            "missing_ranges": _ranges(result.missing),
            "length_error_ranges": _ranges(result.bad_length),
            "block_digest_error_ranges": _ranges(result.bad_digest),
            "unlocatable_digest_mismatch": result.unlocatable_digest_mismatch,
            "abnormal_ranges": _ranges(abnormal),
            "repaired_ranges": [],
            "receipt_sha256": receipt["sha256"],
            "sealed_at": receipt["sealed_at"],
            "checked_at": _utcnow(),
        }

    def audit(self, session: str) -> Optional[dict]:
        """Re-verify a sealed session. Never touches upload progress.

        Returns None for an unknown session; raises ConflictError for an
        unsealed one. A legacy session that passes gets its trusted index
        backfilled. An interrupted-but-already-converged repair marker is
        finalized; an actually pending repair is reported promptly as
        REPAIRING with the scope frozen when that repair started — this
        never waits for the repair's chunk-replacement loop to finish.
        """
        _validate_session(session)
        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                return None
            receipt = self._read_receipt(session)
            if receipt is None:
                raise ConflictError(
                    "session is not sealed: integrity audit is only available "
                    "after sealing and never changes upload progress",
                    reason="not_sealed",
                )
            repair_lock = self._repair_locks.setdefault(session, threading.Lock())

        # Never block behind an in-flight repair: take the per-session lock
        # only if it is free right now.
        acquired = repair_lock.acquire(blocking=False)
        try:
            if not acquired:
                # A repair is actively applying chunks in another thread;
                # answer immediately from its frozen, drift-free plan.
                return self._audit_active_repair(session, meta, receipt)

            with self._lock:
                has_source = os.path.exists(self._repair_source_path(session))

            if not has_source:
                # No repair is active and, while we hold the repair lock,
                # none can start in this process. A plan.json here without a
                # source can only be a cleanup-cut-short orphan: discard it.
                with self._lock:
                    if os.path.exists(self._repair_plan_path(session)):
                        with contextlib.suppress(FileNotFoundError, OSError):
                            os.unlink(self._repair_plan_path(session))
                        with contextlib.suppress(OSError):
                            os.rmdir(self._repair_dir(session))
                        with contextlib.suppress(OSError):
                            _fsync_dir(self._dir(session))

                # Holding the repair lock also means no repair in this
                # process can start or apply chunks while we classify, so
                # the result is a consistent snapshot.
                result, backfill = self._classify(session, meta, receipt)
                if backfill is not None:
                    with self._lock:
                        self._write_index(session, meta, backfill)
                    result.index_present = True
                status = HEALTHY if result.is_clean() else DEGRADED
                return self._audit_payload(session, result, receipt, status)

            # Source exists but nobody in this process is applying: it is an
            # interruption leftover (or another process is repairing).
            return self._audit_dormant_marker(session, meta, receipt)
        finally:
            if acquired:
                repair_lock.release()

    def _audit_active_repair(
        self, session: str, meta: Metadata, receipt: dict
    ) -> dict:
        """REPAIRING while a repair thread holds the session lock."""
        plan = self._read_plan(session)
        if plan is not None:
            return self._repairing_payload(session, plan, receipt)
        if not os.path.exists(self._repair_source_path(session)):
            # The lock is held only by the final teardown now: both markers
            # are already gone (source is unlinked before plan) and every
            # chunk is restored, so report the real converged state instead
            # of an empty REPAIRING.
            result, backfill = self._classify(session, meta, receipt)
            if backfill is not None:
                with self._lock:
                    self._write_index(session, meta, backfill)
                result.index_present = True
            status = HEALTHY if result.is_clean() else DEGRADED
            return self._audit_payload(session, result, receipt, status)
        # Tiny window between source publication and plan.json publication:
        # answer promptly from a lock-free live classification instead of
        # waiting for the repair to finish. No chunk is replaced in this
        # window (replacement starts only after the plan is frozen), so the
        # live scope is exactly the scope the plan will freeze.
        result, _backfill = self._classify(session, meta, receipt)
        return self._audit_payload(session, result, receipt, REPAIRING)

    def _audit_dormant_marker(
        self, session: str, meta: Metadata, receipt: dict
    ) -> dict:
        """Finalize an interrupted repair that already converged; otherwise
        report REPAIRING (this never starts applying chunks)."""
        result, backfill = self._classify(session, meta, receipt)
        if (
            result.is_clean()
            and self._whole_digest(session, meta) == receipt["sha256"]
        ):
            # All chunks already match; only the cleanup was cut off. No
            # chunk is written here, the marker is just finalized.
            with self._lock:
                if not os.path.exists(self._repair_source_path(session)):
                    # Another repair/applier finished concurrently: re-audit
                    # from the now marker-free state.
                    if backfill is not None:
                        self._write_index(session, meta, backfill)
                        result.index_present = True
                    return self._audit_payload(
                        session, result, receipt, HEALTHY
                    )
                if backfill is not None:
                    self._write_index(session, meta, backfill)
                elif not result.index_present:
                    self._backfill_index_from_source(session, meta)
                self._remove_repair_dir(session)
            return self._audit_payload(session, result, receipt, HEALTHY)

        plan = self._read_plan(session)
        if plan is not None:
            return self._repairing_payload(session, plan, receipt)
        # Marker from an older-version interruption without a frozen plan:
        # report the current live scope (audit never repairs).
        return self._audit_payload(session, result, receipt, REPAIRING)

    def _repairing_payload(
        self, session: str, plan: dict, receipt: dict
    ) -> dict:
        """Build REPAIRING from the repair-start snapshot (never drifts)."""
        result = self._plan_classification(plan)
        payload = self._audit_payload(session, result, receipt, REPAIRING)
        payload["repaired_ranges"] = []
        payload["repair_started_at"] = plan.get("started_at")
        return payload

    # ---- original-file repair -------------------------------------------

    def repair(self, session: str, data: bytes) -> Optional[dict]:
        """Repair abnormal chunks from the complete original file.

        The uploaded bytes must match BOTH the receipt length and its
        whole-file digest before any sealed chunk is touched. A validated
        copy is staged as repair/source (the persistent progress marker)
        and the abnormal-block scope is frozen to repair/plan.json before
        the first block is replaced; concurrent audits therefore report a
        stable REPAIRING scope throughout the whole repair window.

        The (potentially long) replacement loop runs OUTSIDE the global
        lock under a per-session repair lock, so concurrent audits stay
        responsive and repeated repairs of the same session serialize.
        Chunk replacement is idempotent and resumes after interruption or
        restart. The receipt and its sealed_at timestamp never change.
        """
        _validate_session(session)
        if not isinstance(data, (bytes, bytearray)):
            raise RejectError("repair payload must be the raw original file")
        data = bytes(data)

        with self._lock:
            meta = self.get_metadata(session)
            if meta is None:
                return None
            receipt = self._read_receipt(session)
            if receipt is None:
                raise ConflictError(
                    "session is not sealed: repair is only available after sealing",
                    reason="not_sealed",
                )

        # Gate the file BEFORE taking the per-session repair lock: wrong-file
        # attempts are rejected promptly (and never queue behind an
        # in-flight repair) and touch no on-disk state.
        self._validate_against_receipt(data, receipt)

        with self._lock:
            repair_lock = self._repair_locks.setdefault(session, threading.Lock())
        with repair_lock:
            # Re-read after possibly waiting for another repair to finish.
            with self._lock:
                meta = self.get_metadata(session)
                receipt = self._read_receipt(session)
            if meta is None or receipt is None:
                raise RejectError("session vanished while waiting for repair")
            self._validate_against_receipt(data, receipt)

            if not os.path.exists(self._repair_source_path(session)):
                # Long spool write: no global lock needed, the per-session
                # repair lock already excludes other appliers.
                # A plan.json without a source can only be a cleanup-cut-short
                # orphan; drop it so this repair freezes a fresh scope.
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._repair_plan_path(session))
                self._stage_source(session, data)

            plan = self._read_plan(session)
            if plan is None:
                # Freeze the scope BEFORE any block is replaced by this
                # repair, so concurrent audits never see drifting ranges.
                # Disk reads stay outside the global lock; no other applier
                # of this session can run, and sealed chunks are otherwise
                # immutable.
                result, _backfill = self._classify(session, meta, receipt)
                with self._lock:
                    self._write_plan(session, self._plan_payload(result))

            return self._apply_validated_source(session)

    @staticmethod
    def _validate_against_receipt(data: bytes, receipt: dict) -> None:
        if len(data) != int(receipt["total_size"]):
            raise ConflictError(
                f"uploaded file length {len(data)} does not match receipt "
                f"length {receipt['total_size']}",
                reason="length_mismatch",
            )
        if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
            raise ConflictError(
                "uploaded file SHA-256 does not match the receipt digest",
                reason="digest_mismatch",
            )

    # ---- frozen repair plan ---------------------------------------------

    def _plan_payload(self, result: _Classification) -> dict:
        return {
            "version": _REPAIR_PLAN_VERSION,
            "missing_ranges": _ranges(result.missing),
            "length_error_ranges": _ranges(result.bad_length),
            "block_digest_error_ranges": _ranges(result.bad_digest),
            "abnormal_ranges": _ranges(result.abnormal()),
            "unlocatable_digest_mismatch": result.unlocatable_digest_mismatch,
            "block_index": result.index_present,
            "started_at": _utcnow(),
        }

    def _write_plan(self, session: str, payload: dict) -> None:
        _atomic_write(
            self._repair_plan_path(session),
            json.dumps(payload, indent=2).encode(),
        )

    def _read_plan(self, session: str) -> Optional[dict]:
        """Load the frozen plan; a missing/malformed plan is reported as
        None (callers fall back to a live classification)."""
        try:
            raw = _read_json(self._repair_plan_path(session))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        try:
            if int(raw.get("version")) != _REPAIR_PLAN_VERSION:
                return None
            ranges_keys = (
                "missing_ranges",
                "length_error_ranges",
                "block_digest_error_ranges",
                "abnormal_ranges",
            )
            for key in ranges_keys:
                for pair in raw[key]:
                    if (
                        not isinstance(pair, list)
                        or len(pair) != 2
                        or int(pair[0]) < 0
                        or int(pair[0]) > int(pair[1])
                    ):
                        return None
            if not isinstance(raw["unlocatable_digest_mismatch"], bool):
                return None
            if not isinstance(raw["block_index"], bool):
                return None
        except (KeyError, TypeError, ValueError):
            return None
        return raw

    @staticmethod
    def _plan_classification(plan: dict) -> _Classification:
        def expand(ranges: list) -> set[int]:
            out: set[int] = set()
            for start, end in ranges:
                out.update(range(int(start), int(end) + 1))
            return out

        return _Classification(
            missing=expand(plan["missing_ranges"]),
            bad_length=expand(plan["length_error_ranges"]),
            bad_digest=expand(plan["block_digest_error_ranges"]),
            unlocatable_digest_mismatch=bool(
                plan["unlocatable_digest_mismatch"]
            ),
            index_present=bool(plan["block_index"]),
        )

    # ---- repair application ---------------------------------------------

    def _stage_source(self, session: str, data: bytes) -> None:
        repair_dir = self._repair_dir(session)
        os.makedirs(repair_dir, exist_ok=True)
        # Spool to a temp file, fsync, then atomically publish: source only
        # ever appears fully validated.
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=repair_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._repair_source_path(session))
            _fsync_dir(repair_dir)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    def _apply_validated_source(self, session: str) -> dict:
        """Replace every abnormal chunk from repair/source; idempotent.

        Runs under the session's repair lock (callers and startup resume
        guarantee it). Re-running converges from any interruption point
        because each chunk replacement is itself atomic and healthy chunks
        are skipped.
        """
        meta = self.get_metadata(session)
        receipt = self._read_receipt(session)
        if meta is None or receipt is None:
            raise RejectError("repair source exists but session metadata is gone")
        source_path = self._repair_source_path(session)
        with open(source_path, "rb") as fh:
            source = fh.read()
        # Re-validate the staged source before trusting it (tamper-proofing).
        if len(source) != int(receipt["total_size"]) or hashlib.sha256(
            source
        ).hexdigest() != receipt["sha256"]:
            with contextlib.suppress(OSError):
                os.unlink(source_path)
            raise ConflictError(
                "staged repair source no longer matches the receipt; resend the file",
                reason="digest_mismatch",
            )

        repaired: list[int] = []
        for i in range(meta.chunk_count):
            start = i * CHUNK_SIZE
            expected = source[start : start + self._expected_block_size(meta, i)]
            path = self._chunk_path(session, i)
            current = self._read_block(session, i)
            if current != expected:
                # Missing, wrong-length or bit-rotted block: the only code
                # path allowed to write into a sealed session's chunks.
                _atomic_write(path, expected)
                repaired.append(i)
                if _REPAIR_CHUNK_DELAY > 0:
                    # Test/ops knob (REPAIR_CHUNK_DELAY seconds per replaced
                    # block, default 0): widens the observable repair window.
                    _sleep(_REPAIR_CHUNK_DELAY)

        if self._whole_digest(session, meta) != receipt["sha256"]:
            # Extremely defensive: leave the marker so the next attempt
            # resumes instead of silently declaring success.
            raise ConflictError(
                "repair could not converge; resend the original file",
                reason="not_converged",
            )

        # The validated original is authoritative: always (re)build the
        # trusted index from it, even if a stale/tampered index was present.
        entries = [
            {
                "index": i,
                "size": self._expected_block_size(meta, i),
                "sha256": hashlib.sha256(
                    source[
                        i * CHUNK_SIZE : i * CHUNK_SIZE
                        + self._expected_block_size(meta, i)
                    ]
                ).hexdigest(),
            }
            for i in range(meta.chunk_count)
        ]
        self._write_index(session, meta, entries)

        self._remove_repair_dir(session)
        return {
            "session": session,
            "status": HEALTHY,
            "sealed": True,
            "repaired_ranges": _ranges(set(repaired)),
            "abnormal_ranges": [],
            "already_healthy": not repaired,
            "receipt_sha256": receipt["sha256"],
            "sealed_at": receipt["sealed_at"],
            "completed_at": _utcnow(),
        }

    def _backfill_index_from_source(self, session: str, meta: Metadata) -> None:
        with open(self._repair_source_path(session), "rb") as fh:
            source = fh.read()
        entries = [
            {
                "index": i,
                "size": self._expected_block_size(meta, i),
                "sha256": hashlib.sha256(
                    source[
                        i * CHUNK_SIZE : i * CHUNK_SIZE
                        + self._expected_block_size(meta, i)
                    ]
                ).hexdigest(),
            }
            for i in range(meta.chunk_count)
        ]
        self._write_index(session, meta, entries)

    def _remove_repair_dir(self, session: str) -> None:
        repair_dir = self._repair_dir(session)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._repair_source_path(session))
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._repair_plan_path(session))
        with contextlib.suppress(FileNotFoundError, OSError):
            os.rmdir(repair_dir)
        with contextlib.suppress(OSError):
            _fsync_dir(self._dir(session))

    def _resume_all_repairs(self) -> None:
        """Continue interrupted repairs at startup; never raise."""
        try:
            names = os.listdir(self.root)
        except OSError:
            return
        for name in names:
            if not re.match(r"^[A-Za-z0-9]{1,32}$", name):
                continue
            if not os.path.isdir(os.path.join(self.root, name)):
                continue
            repair_lock = self._repair_locks.setdefault(name, threading.Lock())
            with repair_lock:
                try:
                    if not os.path.exists(self._repair_source_path(name)):
                        # Orphaned plan.json from a cleanup cut short (source
                        # was unlinked first); no repair can resume without a
                        # source, so drop the stale scope snapshot.
                        with contextlib.suppress(FileNotFoundError):
                            os.unlink(self._repair_plan_path(name))
                        continue
                    with self._lock:
                        meta = self.get_metadata(name)
                        receipt = self._read_receipt(name)
                        if meta is None or receipt is None:
                            continue
                    plan = self._read_plan(name)
                    if plan is None:
                        # Repair started by a crashed process before the
                        # scope could be frozen: freeze it now, then resume.
                        result, _backfill = self._classify(
                            name, meta, receipt
                        )
                        with self._lock:
                            self._write_plan(
                                name, self._plan_payload(result)
                            )
                    self._apply_validated_source(name)
                except Exception:
                    # Leave the persistent state in place for the next
                    # /repair request (or the next restart) to retry.
                    continue
