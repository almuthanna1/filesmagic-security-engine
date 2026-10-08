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

export interface ScanResult {
  filename: string;
  verdict: Verdict;
  findings: Finding[];
  message: string;
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
    VERDICTS.includes(r.verdict) &&
    typeof r.message === "string" &&
    Array.isArray(r.findings) &&
    r.findings.every(isFinding)
  );
}

export async function scanFile(file: File): Promise<ScanResult> {
  if (!API_URL) {
    throw new ApiError(
      "NEXT_PUBLIC_SECURITY_ENGINE_URL is not set. Configure frontend/.env.local and restart the dev server.",
    );
  }

  const body = new FormData();
  body.append("file", file);

  let response: Response;
  try {
    response = await fetch(`${API_URL.replace(/\/+$/, "")}/scan`, { method: "POST", body });
  } catch {
    throw new ApiError(`Could not reach the Security Engine at ${API_URL}. Is the API running?`);
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    data = undefined;
  }

  if (!response.ok) {
    const detail = (data as { detail?: unknown } | undefined)?.detail;
    const suffix = typeof detail === "string" ? `: ${detail}` : "";
    throw new ApiError(`The Security Engine returned HTTP ${response.status}${suffix}.`);
  }

  if (!isScanResult(data)) {
    throw new ApiError("The Security Engine returned a response in an unexpected format.");
  }
  return data;
}
