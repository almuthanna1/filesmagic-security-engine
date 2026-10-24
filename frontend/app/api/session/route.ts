import { NextResponse, type NextRequest } from "next/server";
import { checkPassword, createSession, NotConfiguredError, SESSION_COOKIE, sessionCookieOptions, validSession } from "@/lib/auth";

const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
// ponytail: per-instance memory, so the limit is per Vercel function instance. scrypt keeps each
// guess slow; a long random password is the real defence. Use a shared store (e.g. Upstash) if needed.
const failures = new Map<string, number[]>();

function json(body: object, status = 200) {
  return NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function GET(request: NextRequest) {
  try {
    return json({ authenticated: validSession(request.cookies.get(SESSION_COOKIE)?.value) });
  } catch (e) {
    if (e instanceof NotConfiguredError) return json({ authenticated: false });
    throw e;
  }
}

// Log in.
export async function POST(request: NextRequest) {
  // Vercel sets X-Forwarded-For itself; the first entry is the client address.
  const client = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || "local";
  const now = Date.now();
  const recent = (failures.get(client) ?? []).filter((t) => t > now - WINDOW_MS);
  if (recent.length >= MAX_FAILURES) {
    return json({ detail: "Too many failed attempts. Try again in 15 minutes." }, 429);
  }

  const body = (await request.json().catch(() => null)) as { password?: unknown } | null;
  const password = body?.password;
  if (typeof password !== "string" || password.length === 0 || password.length > 256) {
    return json({ detail: "Enter the password." }, 400);
  }

  let ok: boolean;
  try {
    ok = checkPassword(password);
  } catch (e) {
    if (e instanceof NotConfiguredError) return json({ detail: "Login is not configured on this deployment." }, 503);
    throw e;
  }
  if (!ok) {
    if (failures.size > 10_000) failures.clear();
    failures.set(client, [...recent, now]);
    return json({ detail: "Incorrect password." }, 401);
  }

  failures.delete(client);
  const response = json({ authenticated: true });
  response.cookies.set(SESSION_COOKIE, createSession(), sessionCookieOptions);
  return response;
}

// Log out.
export async function DELETE() {
  const response = json({ authenticated: false });
  response.cookies.set(SESSION_COOKIE, "", { ...sessionCookieOptions, maxAge: 0 });
  return response;
}
