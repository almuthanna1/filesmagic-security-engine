import { NextResponse, type NextRequest } from "next/server";
import { MAX_UPLOAD_BYTES, mintScanToken, NotConfiguredError, UPLOAD_TOO_LARGE } from "@/lib/auth";

// Passwordless research staging. Anyone with this endpoint can request a short-lived token.
// Keep the per-file signature, upload size bound and a basic best-effort, per-instance throttle.
// This in-memory limit is NOT a distributed rate limit across Vercel instances.
const WINDOW_MS = 15 * 60 * 1000;
const MAX_TOKENS_PER_WINDOW = 12;
const issued = new Map<string, number[]>();

// Only the SHA-256 and size reach Vercel; file bytes go directly to Render.
export async function POST(request: NextRequest) {
  const headers = { "Cache-Control": "no-store" };
  try {
    const body = (await request.json().catch(() => null)) as { sha256?: unknown; size?: unknown } | null;
    const { sha256, size } = body ?? {};
    if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256) ||
        typeof size !== "number" || !Number.isInteger(size) || size < 0) {
      return NextResponse.json({ detail: "Invalid file description." }, { status: 400, headers });
    }
    if (size > MAX_UPLOAD_BYTES) {
      return NextResponse.json({ detail: UPLOAD_TOO_LARGE }, { status: 413, headers });
    }
    // Vercel sets x-forwarded-for at its trusted edge; this is only a per-instance
    // best-effort throttle, not an identity check or a security boundary.
    const client = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const now = Date.now();
    const recent = (issued.get(client) ?? []).filter(t => t > now - WINDOW_MS);
    if (recent.length >= MAX_TOKENS_PER_WINDOW) {
      issued.set(client, recent);
      return NextResponse.json({ detail: "Scan limit reached. Please try again in 15 minutes." },
        { status: 429, headers: { ...headers, "Retry-After": "900" } });
    }
    if (issued.size > 10_000) issued.clear();
    issued.set(client, [...recent, now]);
    return NextResponse.json({ token: mintScanToken(sha256, size) }, { headers });
  } catch (e) {
    if (e instanceof NotConfiguredError) {
      return NextResponse.json({ detail: "Scanning is not configured on this deployment." }, { status: 503, headers });
    }
    throw e;
  }
}
