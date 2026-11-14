// Client for the FilesMagic Security Engine API. All backend calls go through here.

export const VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"] as const;
export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type Verdict = (typeof VERDICTS)[number];
export type Severity = (typeof SEVERITIES)[number];

// reference: the four original scanners (what FilesMagic uses); unified: the custom engine candidate,
// accepted only by engines started with SECURITY_ENGINE_RESEARCH_ENGINES=1.
export const ENGINES = ["reference", "unified"] as const;
export type Engine = (typeof ENGINES)[number];
export const ENGINE_LABELS: Record<Engine, string> = {
  reference: "Original Engine",
  unified: "Custom Unified Engine",
};

// Mirrors app/models.py in the engine.
export interface Finding {
  scanner: string;
  category: string;
  severity: Severity;
  description: string;
  rule_id: string | null;
  // Custom engine findings: every action chain, call path or relationship chain behind them.
  evidence?: string[];
}

export interface ScannerStatus {
  name: string;
  status: "completed" | "not_applicable" | "failed";
  error: string | null;
  // malformed_input / invalid_structure: expected for broken or hostile files;
  // unexpected: possible scanner bug; worker: the isolated worker crashed or timed out.
  error_kind: "malformed_input" | "invalid_structure" | "unexpected" | "worker" | null;
  error_type: string | null;
  // Time this scanner spent inside the isolated worker; null if the worker never reported it.
  duration_ms?: number | null;
}

export interface CoverageIssue {
  code: string;
  scanner: string;
  detail: string;
}

export interface ScanResult {
  request_id: string;
  // The engine that produced this result, as reported by the API.
  engine: Engine;
  filename: string;
  verdict: Verdict;
  findings: Finding[];
  message: string;
  sha256: string;
  size_bytes: number;
  detected_format: string;
  scanners: ScannerStatus[];
  complete: boolean;
  coverage_complete: boolean;
  coverage_issues: CoverageIssue[];
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
    ENGINES.includes(r.engine) &&
    VERDICTS.includes(r.verdict) &&
    typeof r.message === "string" &&
    Array.isArray(r.findings) &&
    r.findings.every(isFinding) &&
    typeof r.sha256 === "string" &&
    typeof r.duration_ms === "number" &&
    typeof r.complete === "boolean" &&
    typeof r.coverage_complete === "boolean" &&
    Array.isArray(r.coverage_issues) &&
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
  const token = (data as { token?: unknown } | undefined)?.token;
  if (!response.ok || typeof token !== "string") {
    throw new ApiError(detailOf(data) || `Could not authorize the scan (HTTP ${response.status}).`);
  }
  return token;
}

export interface EngineHealth {
  engines: Engine[];
  defaultEngine: Engine;
  commit: string;
}

export type HealthResult = EngineHealth | { error: string };

// A sleeping instance (Render's Free plan) can answer 5xx or drop the connection for a while as it
// wakes, so those are retried after these delays (5 attempts, 30 s of waiting at most). Each request
// keeps the browser's own timeout. A 4xx or a reply without an engine list is not a cold start and
// fails at once.
export const HEALTH_RETRY_DELAYS_MS = [2000, 4000, 8000, 16000];

// The browser reads the engine list through the Lab's own route (app/api/engines), not the API's
// /health directly: browser privacy/ad-block filters can block third-party requests to */health*
// paths (observed on staging: every attempt failed in the browser while the API answered 200).
export const ENGINES_ROUTE = "/api/engines";

const wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

// Server side of ENGINES_ROUTE: the API's GET /health, passed through. A dropped or timed-out
// connection becomes 502, so the browser retries it like a cold start.
export async function relayHealth(
  base: string | undefined = API_URL,
  get: (url: string) => Promise<Response> = url => fetch(url, { cache: "no-store", signal: AbortSignal.timeout(20_000) }),
): Promise<Response> {
  const headers = { "Cache-Control": "no-store", "Content-Type": "application/json" };
  if (!base) return new Response(JSON.stringify({ detail: "NEXT_PUBLIC_SECURITY_ENGINE_URL is not set." }), { status: 500, headers });
  try {
    const upstream = await get(`${base.replace(/\/+$/, "")}/health`);
    return new Response(await upstream.text(), { status: upstream.status, headers });
  } catch {
    return new Response(JSON.stringify({ detail: "The Security Engine API did not answer." }), { status: 502, headers });
  }
}

// Which engines this API accepts (GET /health, via ENGINES_ROUTE). On failure, the reason; the page
// then offers the original engine only.
export async function engineHealth(
  onRetry?: (attempt: number, attempts: number) => void,
  get: (url: string) => Promise<Response> = url => fetch(url, { cache: "no-store" }),
  sleep: (ms: number) => Promise<void> = wait,
): Promise<HealthResult> {
  if (!API_URL) return { error: "NEXT_PUBLIC_SECURITY_ENGINE_URL is not set." };
  const url = ENGINES_ROUTE;
  const attempts = HEALTH_RETRY_DELAYS_MS.length + 1;
  let last = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1) {
      onRetry?.(attempt, attempts);
      await sleep(HEALTH_RETRY_DELAYS_MS[attempt - 2]);
    }
    let response: Response;
    try {
      response = await get(url);
    } catch {
      last = "no response (network error or blocked request)";
      continue;
    }
    const data = (await readJson(response)) as { engines?: unknown; default_engine?: unknown; commit?: unknown } | undefined;
    if (response.ok && Array.isArray(data?.engines)) {
      return {
        engines: data.engines.filter((e): e is Engine => ENGINES.includes(e as Engine)),
        defaultEngine: data.default_engine === "unified" ? "unified" : "reference",
        commit: typeof data.commit === "string" ? data.commit : "unknown",
      };
    }
    if (response.ok) return { error: "the API's /health reports no engine list (an older engine version)." };
    last = `HTTP ${response.status}`;
    if (response.status < 500) return { error: `the API's /health answered ${last}.` };
  }
  return { error: `the API did not answer after ${attempts} attempts over about 30 s (last: ${last}).` };
}

// After a failed check, check again in the background so the page recovers by itself (a cold start
// longer than the retry window, a transient outage) without a reload.
export const RECHECK_DELAY_MS = 60_000;
export const AUTO_RECHECKS = 10; // ponytail: about 15 minutes of re-checks, then only the Retry button

// Reports every check through onResult; stops at the first success, after AUTO_RECHECKS failed
// re-checks, or when the returned stop() is called (a manual retry starts a new watch).
export function watchEngineHealth(
  onResult: (health: HealthResult) => void,
  onRetry?: (attempt: number, attempts: number) => void,
  check: (onRetry?: (attempt: number, attempts: number) => void) => Promise<HealthResult> = engineHealth,
  sleep: (ms: number) => Promise<void> = wait,
): () => void {
  let stopped = false;
  void (async () => {
    for (let recheck = 0; !stopped; recheck++) {
      const health = await check(onRetry);
      if (stopped) return;
      onResult(health);
      if (!("error" in health) || recheck >= AUTO_RECHECKS) return;
      await sleep(RECHECK_DELAY_MS);
    }
  })();
  return () => { stopped = true; };
}

// 1. Hash the file in the browser. 2. Ask the Lab (server-side, no login) for a
// short-lived token bound to that hash and size. 3. Upload the raw file straight to the engine,
// naming the engine to run. The file never passes through Vercel.
export async function scanFile(file: File, engine: Engine = "reference"): Promise<ScanResult> {
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
      response = await fetch(`${API_URL.replace(/\/+$/, "")}/scan?engine=${engine}`, {
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
  // Never show one engine's result as another's.
  if (data.engine !== engine) {
    throw new ApiError(`Requested the ${ENGINE_LABELS[engine]}, but the response came from the ${ENGINE_LABELS[data.engine]}.`);
  }
  return data;
}
