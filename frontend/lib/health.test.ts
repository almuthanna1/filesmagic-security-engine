import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NEXT_PUBLIC_SECURITY_ENGINE_URL = "https://engine.test/";
const { engineHealth, HEALTH_RETRY_DELAYS_MS, ENGINES_ROUTE, relayHealth, watchEngineHealth, RECHECK_DELAY_MS, AUTO_RECHECKS } =
  await import("./api.ts");

const ok = () => new Response(JSON.stringify({ engines: ["reference", "unified"], default_engine: "reference", commit: "abc" }));
const status = (code: number) => () => new Response("{}", { status: code });
const dropped = () => { throw new TypeError("Failed to fetch"); };

async function run(replies: Array<() => Response>) {
  const slept: number[] = [], retries: number[] = [];
  let calls = 0;
  const result = await engineHealth(
    attempt => retries.push(attempt),
    // Same-origin: the browser never asks the API's /health directly (filters block */health*).
    async url => { assert.equal(url, ENGINES_ROUTE); return replies[Math.min(calls++, replies.length - 1)](); },
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

test("the Lab route relays the API's /health, and a dropped connection becomes a retryable 502", async () => {
  const relayed = await relayHealth("https://engine.test/", async url => {
    assert.equal(url, "https://engine.test/health");
    return ok();
  });
  assert.equal(relayed.status, 200);
  assert.deepEqual((await relayed.json()).engines, ["reference", "unified"]);
  assert.equal(relayed.headers.get("Cache-Control"), "no-store");

  assert.equal((await relayHealth("https://engine.test", async () => status(503)())).status, 503);
  assert.equal((await relayHealth("https://engine.test", async () => dropped())).status, 502);
});

const failed = { error: "the API did not answer after 5 attempts over about 30 s (last: HTTP 502)." };
const healthy = { engines: ["reference", "unified"] as const, defaultEngine: "reference" as const, commit: "abc" };

async function watch(results: Array<typeof failed | typeof healthy>, stopAfter = Infinity) {
  const seen: unknown[] = [], slept: number[] = [];
  let checks = 0, stop = () => {};
  stop = watchEngineHealth(
    health => { seen.push(health); if (seen.length >= stopAfter) stop(); },
    undefined,
    async () => results[Math.min(checks++, results.length - 1)] as never,
    async ms => { slept.push(ms); },
  );
  // The fakes never wait, so the watch ends (success, bound or stop) within a few event-loop turns.
  for (let turn = 0; turn < 50; turn++) await new Promise(r => setImmediate(r));
  return { seen, slept, checks };
}

test("a failed connection recovers by itself: a later successful check reports both engines", async () => {
  const { seen, slept, checks } = await watch([failed, failed, healthy]);
  assert.deepEqual(seen, [failed, failed, healthy]);
  assert.deepEqual(slept, [RECHECK_DELAY_MS, RECHECK_DELAY_MS]);
  assert.equal(checks, 3, "no further checks after the first success");
});

test("background re-checks are bounded when the API never answers", async () => {
  const { seen, checks } = await watch([failed]);
  assert.equal(checks, AUTO_RECHECKS + 1);
  assert.ok(seen.every(h => h === failed));
});

test("stop() (unmount or a manual Retry) ends the watch", async () => {
  const { seen, checks } = await watch([failed], 1);
  assert.equal(seen.length, 1);
  assert.equal(checks, 1);
});
