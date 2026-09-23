// Typed client for the sealing-desk HTTP API.

export const CHUNK_SIZE = 65536;
export const MIN_FILE_SIZE = 1;
export const MAX_FILE_SIZE = 8 * 1024 * 1024;
export const SESSION_RE = /^[A-Za-z0-9]{1,32}$/;

export interface ChunkAck {
  session: string;
  offset: number;
  index: number;
  size: number;
  duplicate: boolean;
  confirmed_chunks: number[];
  chunk_count: number;
  missing_ranges: [number, number][];
  sealed: boolean;
}

export interface Receipt {
  receipt_id: string;
  session: string;
  total_size: number;
  sha256: string;
  chunks: number;
  chunk_size: number;
  sealed_at: string;
}

export interface SessionStatus {
  session: string;
  total_size: number;
  sha256: string;
  chunk_count: number;
  confirmed_chunks: number[];
  missing_ranges: [number, number][];
  sealed: boolean;
  receipt: Receipt | null;
}

export type AuditStatus = "HEALTHY" | "DEGRADED" | "REPAIRING";

export interface AuditResult {
  session: string;
  status: AuditStatus;
  sealed: boolean;
  block_index: boolean;
  missing_ranges: [number, number][];
  length_error_ranges: [number, number][];
  block_digest_error_ranges: [number, number][];
  unlocatable_digest_mismatch: boolean;
  abnormal_ranges: [number, number][];
  repaired_ranges: [number, number][];
  receipt_sha256: string;
  sealed_at: string;
  checked_at?: string;
  completed_at?: string;
  already_healthy?: boolean;
}

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let body: unknown = null;
  let message = `${res.status} ${res.statusText}`;
  try {
    body = await res.json();
    if (body && typeof body === "object" && "error" in body) {
      message = String((body as { error: unknown }).error);
    } else if (body && typeof body === "object" && "detail" in body) {
      message = String((body as { detail: unknown }).detail);
    }
  } catch {
    // non-JSON error body: keep the status-line message
  }
  return new ApiError(res.status, message, body);
}

export async function fetchStatus(session: string): Promise<SessionStatus | null> {
  const res = await fetch(`/api/uploads/${session}`);
  if (res.status === 404) return null;
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as SessionStatus;
}

export async function putChunk(
  session: string,
  offset: number,
  bytes: ArrayBuffer,
  totalSize: number,
  sha256: string
): Promise<ChunkAck> {
  const res = await fetch(`/api/uploads/${session}/chunks`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Chunk-Offset": String(offset),
      "X-Total-Size": String(totalSize),
      "X-Content-SHA256": sha256,
    },
    body: bytes,
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as ChunkAck;
}

export interface SealResult {
  status: number;
  receipt: Receipt | null;
  missingRanges: [number, number][] | null;
  error: string | null;
}

export async function seal(session: string): Promise<SealResult> {
  const res = await fetch(`/api/uploads/${session}/seal`, { method: "POST" });
  if (res.ok) {
    return {
      status: res.status,
      receipt: (await res.json()) as Receipt,
      missingRanges: null,
      error: null,
    };
  }
  const err = await parseError(res);
  const ranges =
    err.body &&
    typeof err.body === "object" &&
    "missing_ranges" in err.body
      ? ((err.body as { missing_ranges: [number, number][] }).missing_ranges ?? null)
      : null;
  return { status: res.status, receipt: null, missingRanges: ranges, error: err.message };
}

export async function auditSession(session: string): Promise<AuditResult> {
  const res = await fetch(`/api/uploads/${session}/audit`, { method: "POST" });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as AuditResult;
}

export async function repairSession(
  session: string,
  file: File
): Promise<AuditResult> {
  // Raw octet-stream body: the complete original file. The server gates on
  // receipt length + whole-file SHA-256 before changing any sealed byte.
  const res = await fetch(`/api/uploads/${session}/repair`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: file,
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as AuditResult;
}

import { sha256Bytes } from "./sha256";

function toHex(digest: ArrayBuffer | Uint8Array): string {
  const view =
    digest instanceof Uint8Array ? digest : new Uint8Array(digest);
  return Array.from(view, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Lowercase hex SHA-256 of the whole file, computed in the browser.
 * Prefers WebCrypto; falls back to a pure-TS implementation when the page
 * is not running in a secure context (plain HTTP on a LAN address).
 */
export async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    try {
      return toHex(await crypto.subtle.digest("SHA-256", buffer));
    } catch {
      // fall through to the pure-TS implementation
    }
  }
  return toHex(sha256Bytes(buffer));
}
