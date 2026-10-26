// Client for the FilesMagic Security Engine API. All backend calls go through here.

export const VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"] as const;
export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type Verdict = (typeof VERDICTS)[number];
export type Severity = (typeof SEVERITIES)[number];

// Mirrors app/models.py in the engine.
export interface Finding {
  scanner: string;
  category: string;
  severity: Severity;
  description: string;
  rule_id: string | null;
}

export interface ScannerStatus {
  name: string;
  status: "completed" | "not_applicable" | "failed";
  error: string | null;
  // malformed_input / invalid_structure: expected for broken or hostile files;
  // unexpected: possible scanner bug; worker: the isolated worker crashed or timed out.
  error_kind: "malformed_input" | "invalid_structure" | "unexpected" | "worker" | null;
  error_type: string | null;
}

export interface ScanResult {
  request_id: string;
  filename: string;
  verdict: Verdict;
  findings: Finding[];
  message: string;
  sha256: string;
  size_bytes: number;
  detected_format: string;
  scanners: ScannerStatus[];
  complete: boolean;
  duration_ms: number;
  versions: Record<string, string>;
  // Configured: strict mode (the worker refuses to scan unless every required isolation value is true).
  isolation_required?: boolean;
  // Reported by the worker: applied controls (e.g. network_namespace) and independently
  // verified ones (network_verified and the net_* checks behind it).
  isolation: Record<string, boolean>;
  // Required isolation values that are not true; strict mode analyses only when this is empty.
  isolation_missing?: string[];
}

// Inlined at build time. Set it in frontend/.env.local (see .env.example).
const API_URL = process.env.NEXT_PUBLIC_SECURITY_ENGINE_URL;

export class ApiError extends Error {}
// The Lab session is missing or expired: show the login form.
export class AuthRequiredError extends ApiError {}

function isFinding(value: unknown): value is Finding {
  const f = value as Finding;
  return (
    typeof f === "object" &&
    f !== null &&
    typeof f.scanner === "string" &&
    typeof f.category === "string" &&
    SEVERITIES.includes(f.severity) &&
    typeof f.description === "string" &&
    (f.rule_id === null || f.rule_id === undefined || typeof f.rule_id === "string")
  );
}

function isScanResult(value: unknown): value is ScanResult {
  const r = value as ScanResult;
  return (
    typeof r === "object" &&
    r !== null &&
    typeof r.filename === "string" &&
    VERDICTS.includes(r.verdict) &&
    typeof r.message === "string" &&
    Array.isArray(r.findings) &&
    r.findings.every(isFinding) &&
    typeof r.sha256 === "string" &&
    typeof r.duration_ms === "number" &&
    typeof r.complete === "boolean" &&
    Array.isArray(r.scanners) &&
    typeof r.versions === "object" &&
    typeof r.isolation === "object"
  );
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function detailOf(data: unknown): string {
  const detail = (data as { detail?: unknown } | undefined)?.detail;
  return typeof detail === "string" ? detail : "";
}

export async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Lab session (same-origin route handlers; the session cookie is HttpOnly).
export async function login(password: string): Promise<void> {
  const response = await fetch("/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!response.ok) throw new ApiError(detailOf(await readJson(response)) || `Login failed (HTTP ${response.status}).`);
}

export async function logout(): Promise<void> {
  await fetch("/api/session", { method: "DELETE" });
}

// Must match MAX_UPLOAD_BYTES in the engine (app/main.py) and lib/auth.ts.
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
// Same wording as the engine's HTTP 413 response.
export const UPLOAD_TOO_LARGE = `File is too large. The maximum upload size is ${MAX_UPLOAD_BYTES / (1024 * 1024)} MB.`;

async function scanToken(sha256: string, size: number): Promise<string> {
  const response = await fetch("/api/scan-token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sha256, size }),
  });
  const data = await readJson(response);
  if (response.status === 401) throw new AuthRequiredError(detailOf(data) || "Log in to scan files.");
  const token = (data as { token?: unknown } | undefined)?.token;
  if (!response.ok || typeof token !== "string") {
    throw new ApiError(detailOf(data) || `Could not authorize the scan (HTTP ${response.status}).`);
  }
  return token;
}

// 1. Hash the file in the browser. 2. Ask the Lab (server side, session required) for a
// short-lived token bound to that hash and size. 3. Upload the raw file straight to the engine.
// The file never passes through Vercel.
export async function scanFile(file: File): Promise<ScanResult> {
  if (!API_URL) {
    throw new ApiError(
      "NEXT_PUBLIC_SECURITY_ENGINE_URL is not set. Configure frontend/.env.local and restart the dev server.",
    );
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new ApiError(UPLOAD_TOO_LARGE);
  }

  const sha256 = await sha256Hex(file);
  let response: Response | undefined;
  // A token is single-use and lives 120 s. If the engine rejects it (e.g. it expired while a
  // sleeping free instance woke up), retry once with a fresh token.
  for (let attempt = 0; attempt < 2 && (!response || response.status === 401); attempt++) {
    const token = await scanToken(sha256, file.size);
    try {
      response = await fetch(`${API_URL.replace(/\/+$/, "")}/scan`, {
        method: "POST",
        body: file,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/octet-stream",
          "X-Filename": encodeURIComponent(file.name),
        },
      });
    } catch {
      throw new ApiError(`Could not reach the Security Engine at ${API_URL}. Is the API running?`);
    }
  }

  const data = await readJson(response!);
  if (!response!.ok) {
    const detail = detailOf(data);
    throw new ApiError(`The Security Engine returned HTTP ${response!.status}${detail ? `: ${detail}` : ""}.`);
  }
  if (!isScanResult(data)) {
    throw new ApiError("The Security Engine returned a response in an unexpected format.");
  }
  return data;
}
