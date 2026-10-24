import { NextResponse, type NextRequest } from "next/server";
import { MAX_UPLOAD_BYTES, mintScanToken, NotConfiguredError, SESSION_COOKIE, validSession } from "@/lib/auth";

// Issues a token for one upload. Only the file's hash and size reach Vercel, never its contents:
// the browser sends the file straight to the engine, which checks the token itself.
export async function POST(request: NextRequest) {
  const headers = { "Cache-Control": "no-store" };
  try {
    if (!validSession(request.cookies.get(SESSION_COOKIE)?.value)) {
      return NextResponse.json({ detail: "Log in to scan files." }, { status: 401, headers });
    }
    const body = (await request.json().catch(() => null)) as { sha256?: unknown; size?: unknown } | null;
    const { sha256, size } = body ?? {};
    if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256) ||
        typeof size !== "number" || !Number.isInteger(size) || size < 0 || size > MAX_UPLOAD_BYTES) {
      return NextResponse.json({ detail: "Invalid file description." }, { status: 400, headers });
    }
    return NextResponse.json({ token: mintScanToken(sha256, size) }, { headers });
  } catch (e) {
    if (e instanceof NotConfiguredError) {
      return NextResponse.json({ detail: "Scanning is not configured on this deployment." }, { status: 503, headers });
    }
    throw e;
  }
}
