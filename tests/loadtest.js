#!/usr/bin/env node
/**
 * Load test for POST /api/auth/register
 * Requires Node 18+ (built-in fetch). No dependencies.
 *
 * Examples:
 *   node loadtest.js --total 100 --duration 10         # 100 requests spread evenly over 10s
 *   node loadtest.js --total 5000 --concurrency 100    # 5000 requests, 100 in flight at once
 *   node loadtest.js --total 5000 --duration 60        # 5000 requests paced over 60s
 *
 * Only run this against a server you own. Every request creates a user,
 * so clean up the test users afterwards (they all start with "lt_<runId>_").
 */

const URL = process.env.URL || "https://smartfarmc.bayonos.site/api/auth/register";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => {
    if (a.startsWith("--")) acc.push([a.slice(2), arr[i + 1]]);
    return acc;
  }, [])
);

const TOTAL = parseInt(args.total || "100", 10);
const DURATION = args.duration ? parseFloat(args.duration) : null; // seconds
const CONCURRENCY = parseInt(args.concurrency || "50", 10);
const TIMEOUT_MS = parseInt(args.timeout || "30000", 10);

const runId = Date.now().toString(36);

function buildPayload(i) {
  // username/email/phone must be unique or the server will reject duplicates
  const n = String(i).padStart(6, "0");
  return {
    username: `lt_${runId}_${n}`,
    password: `Pass${Math.floor(Math.random() * 1e8)}`,
    full_name: `Load Test ${n}`,
    email: `lt_${runId}_${n}@efarm.local`,
    phone: `0${String(10000000 + (i % 90000000))}`,
    role: "owner",
  };
}

const latencies = [];
const statusCounts = {};
const errorCounts = {};
let sent = 0;
let done = 0;

const http = require("http");
const https = require("https");
const target = new (require("url").URL)(URL);
const lib = target.protocol === "https:" ? https : http;
const MAX_SOCKETS = parseInt(args.sockets || "100", 10);
// Reuse a limited pool of keep-alive connections instead of opening one per request
const agent = new lib.Agent({ keepAlive: true, maxSockets: MAX_SOCKETS });
const bodySamples = {}; // first response body seen per status code

function request(i) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(buildPayload(i));
    const req = lib.request(
      target,
      {
        method: "POST",
        agent,
        timeout: TIMEOUT_MS,
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, data }));
      }
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "TIMEOUT" })));
    req.on("error", reject);
    req.end(body);
  });
}

async function sendOne(i) {
  const start = performance.now();
  try {
    const { status, data } = await request(i);
    statusCounts[status] = (statusCounts[status] || 0) + 1;
    if (!bodySamples[status]) bodySamples[status] = data.slice(0, 200);
  } catch (e) {
    const key = e.code || e.message;
    errorCounts[key] = (errorCounts[key] || 0) + 1;
  } finally {
    latencies.push(performance.now() - start);
    done++;
  }
}

// ---- client-side resource sampling (this machine, not the server) ----
const samples = [];
let lastCpu = process.cpuUsage();
let lastT = performance.now();
const sampler = setInterval(() => {
  const now = performance.now();
  const cpu = process.cpuUsage(lastCpu);
  const cpuPct = ((cpu.user + cpu.system) / 1000 / (now - lastT)) * 100;
  samples.push({ cpuPct, rssMB: process.memoryUsage().rss / 1048576 });
  lastCpu = process.cpuUsage();
  lastT = now;
}, 1000);

function pct(sorted, p) {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

async function runPaced() {
  // evenly spaced: one request every DURATION/TOTAL seconds
  const interval = (DURATION * 1000) / TOTAL;
  const t0 = performance.now();
  const inflight = [];
  for (let i = 0; i < TOTAL; i++) {
    const target = t0 + i * interval;
    const wait = target - performance.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    sent++;
    inflight.push(sendOne(i));
  }
  await Promise.all(inflight);
}

async function runConcurrent() {
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= TOTAL) return;
      sent++;
      await sendOne(i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, TOTAL) }, worker));
}

(async () => {
  console.log(`Target:  ${URL}`);
  console.log(
    `Plan:    ${TOTAL} requests, ` +
      (DURATION ? `paced over ${DURATION}s (~${(TOTAL / DURATION).toFixed(1)} req/s)` : `concurrency ${CONCURRENCY}`)
  );
  console.log(`Run ID:  ${runId} (usernames: lt_${runId}_*)`);
  console.log(`Sockets: max ${MAX_SOCKETS} keep-alive connections\n`);

  // Preflight: one request to make sure the server is reachable before the real test
  try {
    const t = performance.now();
    const r = await request(-1);
    console.log(`Preflight: HTTP ${r.status} in ${(performance.now() - t).toFixed(0)}ms  ${r.data.slice(0, 150)}\n`);
  } catch (e) {
    console.log(`Preflight FAILED: ${e.code || e.message}`);
    console.log("The server is not reachable from this machine. Check the URL, DNS, firewall/Cloudflare, or whether the app is running.");
    clearInterval(sampler);
    process.exit(1);
  }

  const progress = setInterval(() => process.stdout.write(`\r  sent ${sent}/${TOTAL}  done ${done}   `), 500);
  const t0 = performance.now();
  await (DURATION ? runPaced() : runConcurrent());
  const elapsed = (performance.now() - t0) / 1000;
  clearInterval(progress);
  clearInterval(sampler);

  const sorted = [...latencies].sort((a, b) => a - b);
  const avg = latencies.reduce((a, b) => a + b, 0) / (latencies.length || 1);
  const ok = Object.entries(statusCounts)
    .filter(([s]) => s.startsWith("2"))
    .reduce((a, [, c]) => a + c, 0);

  console.log("\n\n=== RESULTS ===");
  console.log(`Elapsed:        ${elapsed.toFixed(2)}s`);
  console.log(`Throughput:     ${(done / elapsed).toFixed(1)} req/s`);
  console.log(`Success (2xx):  ${ok}/${TOTAL} (${((ok / TOTAL) * 100).toFixed(1)}%)`);
  console.log(`Status codes:   ${JSON.stringify(statusCounts)}`);
  if (Object.keys(errorCounts).length) console.log(`Errors:         ${JSON.stringify(errorCounts)}`);
  for (const [s, b] of Object.entries(bodySamples)) console.log(`Sample ${s}:     ${b}`);
  console.log(
    `Latency (ms):   avg ${avg.toFixed(0)} | p50 ${pct(sorted, 50).toFixed(0)} | p95 ${pct(sorted, 95).toFixed(0)} | p99 ${pct(sorted, 99).toFixed(0)} | max ${(sorted.at(-1) || 0).toFixed(0)}`
  );
  if (samples.length) {
    const maxCpu = Math.max(...samples.map((s) => s.cpuPct));
    const maxMem = Math.max(...samples.map((s) => s.rssMB));
    console.log(`Client (this machine): peak CPU ${maxCpu.toFixed(0)}% | peak RSS ${maxMem.toFixed(0)} MB`);
  }
  console.log("\nNote: server CPU/memory is NOT visible from here - run monitor.sh on the server during the test.");
})();
