import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NEXT_PUBLIC_SECURITY_ENGINE_URL = "https://engine.test/";
const { engineHealth, HEALTH_RETRY_DELAYS_MS } = await import("./api.ts");

const ok = () => new Response(JSON.stringify({ engines: ["reference", "unified"], default_engine: "reference", commit: "abc" }));
const status = (code: number) => () => new Response("{}", { status: code });
const dropped = () => { throw new TypeError("Failed to fetch"); };

async function run(replies: Array<() => Response>) {
  const slept: number[] = [], retries: number[] = [];
  let calls = 0;
  const result = await engineHealth(
    attempt => retries.push(attempt),
    async url => { assert.equal(url, "https://engine.test/health"); return replies[Math.min(calls++, replies.length - 1)](); },
    async ms => { slept.push(ms); },
  );
  return { result, slept, retries, calls };
}

test("a cold start (dropped connection, then 503) is retried until the engine answers", async () => {
  const { result, slept, retries } = await run([dropped, status(503), ok]);
  assert.deepEqual(result, { engines: ["reference", "unified"], defaultEngine: "reference", commit: "abc" });
  assert.deepEqual(slept, [2000, 4000]);
  assert.deepEqual(retries, [2, 3]);
});

test("retries are bounded and the genuine failure is reported", async () => {
  const { result, slept, calls } = await run([status(502)]);
  assert.equal(calls, HEALTH_RETRY_DELAYS_MS.length + 1);
  assert.deepEqual(slept, HEALTH_RETRY_DELAYS_MS);
  assert.ok("error" in result && result.error.includes("5 attempts") && result.error.includes("HTTP 502"));
});

test("a 4xx or a reply without engines is not a cold start: no retry", async () => {
  for (const reply of [status(404), () => new Response(JSON.stringify({ status: "ok" }))]) {
    const { result, calls } = await run([reply]);
    assert.equal(calls, 1);
    assert.ok("error" in result);
  }
});
