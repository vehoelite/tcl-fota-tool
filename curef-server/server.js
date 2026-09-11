#!/usr/bin/env node
/**
 * tcl-curef server — a small, dependency-free registry of the (curef, fv)
 * device identifiers the tcl-fw tool looks up.
 *
 * Why: every TCL device is identified by a `curef` (product id) plus an `fv`
 * (firmware version). The tool can only auto-fill a device it knows about.
 * When users opt in, the tool reports the curef/fv it just used, so the
 * community device list grows by itself. That's the whole purpose.
 *
 * What it stores — ONLY device identifiers, nothing personal:
 *   curef, fv, mode, tv, fw_id, tool_version, first_seen, last_seen, count
 * It does NOT store IMEI (the FOTA protocol uses a fixed placeholder), IP
 * addresses, accounts, or anything that identifies a person.
 *
 * Zero npm dependencies — Node built-ins only, so deployment is just copying
 * this file. Reads are public (so anyone can see what's recorded); writes need
 * a shared key (anti-spam only) and are rate-limited + validated.
 *
 * Env: PORT (default 8788), DATA_DIR (default ./data), TCL_CUREF_KEY (required
 * for writes), FLUSH_MS (default 2000).
 */

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const fota = require("./fota.js");

const PORT = parseInt(process.env.PORT || "8788", 10);
// Bind localhost by default: the server is meant to sit behind a tunnel /
// reverse proxy (Cloudflare Zero Trust), not be exposed directly. Set HOST to
// 0.0.0.0 only if you really want it on a public port (then open the firewall).
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const API_KEY = process.env.TCL_CUREF_KEY || "";
const FLUSH_MS = parseInt(process.env.FLUSH_MS || "2000", 10);

const AGG_FILE = path.join(DATA_DIR, "curefs.json");
const EVENTS_FILE = path.join(DATA_DIR, "events.jsonl");

// ── validation ──────────────────────────────────────────────────────────────
const RE_CUREF = /^[A-Za-z0-9][A-Za-z0-9._-]{2,47}$/;
const RE_FV = /^[A-Za-z0-9]{2,24}$/;
const RE_TVFW = /^[A-Za-z0-9._-]{1,32}$/;
const RE_VER = /^[A-Za-z0-9._+-]{1,32}$/;
const MAX_BODY = 4096;

// ── in-memory state ───────────────────────────────────────────────────────────
/** key `${curef} ${fv} ${mode}` -> record */
const store = new Map();
let dirty = false;
let flushTimer = null;

function loadStore() {
  try {
    const raw = JSON.parse(fs.readFileSync(AGG_FILE, "utf8"));
    for (const rec of raw.records || []) {
      // Use the persisted key. Re-deriving it as `curef fv mode` collapsed every
      // revalidated build (which keys by `curef @tv mode` and has no fv) into a
      // single slot, so each restart silently dropped release history.
      const key = rec._key || `${rec.curef} ${rec.fv} ${rec.mode}`;
      delete rec._key;
      store.set(key, rec);
    }
    log(`loaded ${store.size} records from ${AGG_FILE}`);
  } catch (e) {
    if (e.code !== "ENOENT") log(`load error: ${e.message}`);
  }
}

function scheduleFlush() {
  dirty = true;
  if (flushTimer) return;
  flushTimer = setTimeout(flush, FLUSH_MS);
}

function flush() {
  flushTimer = null;
  if (!dirty) return;
  dirty = false;
  // Persist each record's store key so reload reconstructs the map exactly.
  // _key lives only in the file; the in-memory records (and the public API)
  // never carry it.
  const records = [...store.entries()].map(([key, rec]) => Object.assign({ _key: key }, rec));
  const payload = JSON.stringify({ updated: new Date().toISOString(), count: records.length, records });
  const tmp = AGG_FILE + ".tmp";
  try {
    fs.writeFileSync(tmp, payload);
    fs.renameSync(tmp, AGG_FILE);
  } catch (e) {
    log(`flush error: ${e.message}`);
    dirty = true; // retry next time
  }
}

// ── rate limiting (per IP, sliding window) ────────────────────────────────────
const RATE_MAX = 120;        // requests
const RATE_WINDOW_MS = 60000; // per minute
const hits = new Map();       // ip -> number[] (timestamps)

function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > RATE_MAX;
}
// occasional cleanup so the map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const keep = arr.filter((t) => now - t < RATE_WINDOW_MS);
    if (keep.length) hits.set(ip, keep); else hits.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

// ── helpers ───────────────────────────────────────────────────────────────────
function log(msg) {
  console.log(`${new Date().toISOString()} ${msg}`);
}

function clientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return req.socket.remoteAddress || "?";
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ── the /about transparency page ──────────────────────────────────────────────
function aboutPage() {
  const s = stats();
  return `tcl-curef community device registry
=====================================

This server exists for one purpose: to grow the tcl-fw tool's list of TCL
devices automatically.

WHAT IT RECORDS
  When you look up firmware with tcl-fw AND you have sharing turned on, the
  tool sends the device identifiers it just used:

    curef         e.g. T807W-EATBUS12-V   (the TCL product id)
    fv            e.g. AXAMWTM0           (the firmware version)
    mode          2 (OTA) or 4 (FULL)
    tv, fw_id     the resolved target build, if any
    size, svn     package size and TCL software version, if known
    name          e.g. "TCL 50 XL 5G"     (the device MODEL name, read from
                  a read-only build property - it is identical on every unit
                  of that model, so it names the model, never your phone)
    tool_version  which tcl-fw version reported it

WHAT IT DOES NOT RECORD
  No IMEI or serial (the FOTA protocol uses a fixed placeholder, not your
  real one). No IP addresses. No account. No personal name, e-mail, or
  location. No user-set device nickname. Nothing that identifies you or your
  specific phone — only the model/build identifiers that are the same across
  every identical device.

HOW IT HELPS
  New curef/fv combinations feed the tool's built-in device + firmware
  templates, so the next person with your phone gets auto-detect and a
  validated entry without hunting for anything.

IT IS OPTIONAL
  Sharing is disclosed on first run and can be turned off any time:
      tcl-fw sharing --off
  Read the current status with:
      tcl-fw sharing

WHAT'S RECORDED RIGHT NOW
  ${s.devices} distinct curefs, ${s.combos} curef/fv combinations,
  ${s.total} total submissions. Last updated ${s.updated || "never"}.

  Browse the raw data as JSON:  /api/curefs     (public)
  Summary counts as JSON:       /api/stats      (public)
`;
}

/**
 * Reshape the flat record store into a per-device template feed the client can
 * merge directly: one entry per (curef, mode), each carrying its distinct
 * firmware releases. Only records validated by a real resolve (tv + fw_id
 * present) are included, so nothing unverified propagates into the tool.
 */
function templatesFeed() {
  const byDevice = new Map(); // `${curef} ${mode}` -> { curef, mode, releases: Map }
  for (const r of store.values()) {
    if (!r.tv || !r.fw_id) continue;
    const dkey = `${r.curef} ${r.mode}`;
    let dev = byDevice.get(dkey);
    if (!dev) { dev = { curef: r.curef, mode: r.mode, name: "", releases: new Map() }; byDevice.set(dkey, dev); }
    if (r.name && r.name.length > dev.name.length) dev.name = r.name;
    const rkey = `${r.tv} ${r.fw_id}`;
    const seen = dev.releases.get(rkey);
    // keep the earliest first_seen for a given build; carry size/api if known
    if (!seen || (r.first_seen && r.first_seen < seen.first_seen)) {
      dev.releases.set(rkey, {
        tv: r.tv, fw_id: r.fw_id, first_seen: r.first_seen,
        size: r.size || (seen && seen.size) || null,
        api: r.api || (seen && seen.api) || null,
        svn: r.svn || (seen && seen.svn) || null,
      });
    } else if (seen) {
      if (r.size) seen.size = r.size;
      if (r.api) seen.api = r.api;
      if (r.svn) seen.svn = r.svn;
    }
  }
  return [...byDevice.values()].map((d) => ({
    curef: d.curef,
    name: d.name || "",
    mode: parseInt(d.mode, 10) || 4,
    releases: [...d.releases.values()].sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || "")),
  }));
}

function stats() {
  let total = 0;
  const curefs = new Set();
  let updated = null;
  for (const r of store.values()) {
    total += r.count || 0;
    curefs.add(r.curef);
    if (!updated || (r.last_seen && r.last_seen > updated)) updated = r.last_seen;
  }
  return { devices: curefs.size, combos: store.size, total, updated, last_revalidated: lastRevalidate };
}

// ── request handling ──────────────────────────────────────────────────────────
function handleRecord(req, res, body) {
  if (API_KEY) {
    if (req.headers["x-tcl-key"] !== API_KEY) return sendJson(res, 401, { ok: false, error: "bad or missing key" });
  }
  let data;
  try { data = JSON.parse(body || "{}"); } catch { return sendJson(res, 400, { ok: false, error: "invalid json" }); }

  const curef = String(data.curef || "").trim();
  const fv = String(data.fv || "").trim();
  const mode = String(data.mode || "").trim() || "0";
  if (!RE_CUREF.test(curef)) return sendJson(res, 400, { ok: false, error: "invalid curef" });
  // fv is optional: a FULL lookup without a device attached still teaches us a
  // curef + its target build. When present it must look like a real fv.
  if (fv && !RE_FV.test(fv)) return sendJson(res, 400, { ok: false, error: "invalid fv" });
  if (!["0", "2", "4"].includes(mode)) return sendJson(res, 400, { ok: false, error: "invalid mode" });

  const tv = RE_TVFW.test(String(data.tv || "")) ? String(data.tv) : null;
  const fw_id = RE_TVFW.test(String(data.fw_id || "")) ? String(data.fw_id) : null;
  const ver = RE_VER.test(String(data.tool_version || "")) ? String(data.tool_version) : null;
  const sizeNum = Number(data.size);
  const size = Number.isFinite(sizeNum) && sizeNum > 0 && sizeNum < 1e13 ? Math.floor(sizeNum) : null;
  const apiNum = Number(data.api);
  const api = Number.isInteger(apiNum) && apiNum > 0 && apiNum < 100 ? apiNum : null;
  const svn = RE_VER.test(String(data.svn || "")) ? String(data.svn) : null;  // TCL SW version

  // Device model name: a read-only build prop, identical on every unit of a
  // model. Collapse whitespace, drop control chars, cap the length.
  const name = String(data.name || "")
    .replace(/\s+/g, " ").trim()
    .replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, "")
    .slice(0, 64) || null;

  const { rec, known } = upsert({ curef, fv, mode, tv, fw_id, size, api, svn, name, ver, bump: true });
  if (!known) log(`NEW ${curef} fv=${fv} mode=${mode}`);
  return sendJson(res, 200, { ok: true, known, count: rec.count });
}

/**
 * Insert or update one record. `bump` counts a real user submission;
 * revalidation passes bump=false, validated=true (sets last_validated).
 */
function upsert({ curef, fv = "", mode, tv = null, fw_id = null, size = null,
                  api = null, svn = null, ver = null, name = null,
                  bump = false, validated = false }) {
  const now = new Date().toISOString();
  // User submissions key by fv (their build). Revalidation has no fv, so it
  // keys by the discovered build (tv) instead — each new firmware TCL ships
  // becomes its own record and the release history grows, rather than a single
  // fv="" slot being overwritten. "@" can't collide with a real fv.
  const key = (validated && tv) ? `${curef} @${tv} ${mode}` : `${curef} ${fv} ${mode}`;
  let rec = store.get(key);
  let known = true;
  if (!rec) {
    known = false;
    rec = { curef, fv, mode, tv, fw_id, size: null, api: null, svn: null, name: null, count: 0, first_seen: now, last_seen: now, tool_versions: [] };
    store.set(key, rec);
  }
  if (bump) { rec.count += 1; rec.last_seen = now; }
  if (validated) rec.last_validated = now;
  if (tv) rec.tv = tv;
  if (fw_id) rec.fw_id = fw_id;
  if (size) rec.size = size;
  if (api) rec.api = api;
  if (svn) rec.svn = svn;
  // Device model name (a read-only build prop). Keep the most descriptive one
  // seen: a marketing name ("TCL 50 XL 5G") beats a bare model code ("T807W").
  if (name && (!rec.name || name.length > rec.name.length)) rec.name = name;
  if (ver && !rec.tool_versions.includes(ver)) rec.tool_versions.push(ver);

  // append-only raw event log (best-effort)
  fs.appendFile(EVENTS_FILE, JSON.stringify({ t: now, curef, fv, mode, tv, fw_id, size, api, svn, name, ver, validated }) + "\n", () => {});
  scheduleFlush();
  return { rec, known };
}

// ── re-validation: periodically re-check known curefs against TCL, so new
// firmware for a device grows the history without waiting on a user lookup.
// A new build is stored under fv="" mode="4" (the fv-independent full image).
const REVALIDATE_MS = parseInt(process.env.REVALIDATE_MS || String(12 * 3600 * 1000), 10);
let revalidating = false;
let lastRevalidate = null;

async function revalidateAll() {
  if (revalidating) return { skipped: true };
  revalidating = true;
  const curefs = [...new Set([...store.values()].map((r) => r.curef))].filter((c) => RE_CUREF.test(c));
  let checked = 0, added = 0;
  try {
    for (const curef of curefs) {
      const meta = await fota.check(curef, 4).catch(() => null);
      checked++;
      if (meta && meta.tv && meta.fw_id) {
        const { known } = upsert({
          curef, fv: "", mode: "4", tv: meta.tv, fw_id: meta.fw_id,
          size: meta.size, svn: meta.svn, validated: true,
        });
        if (!known) { added++; log(`REVALIDATE new build ${curef} tv=${meta.tv}`); }
      }
      await new Promise((r) => setTimeout(r, 800));  // be polite to TCL
    }
  } finally {
    revalidating = false;
    lastRevalidate = new Date().toISOString();
    flush();
  }
  log(`revalidate done: ${checked} checked, ${added} new build(s)`);
  return { checked, added };
}

function scheduleRevalidation() {
  if (!REVALIDATE_MS || REVALIDATE_MS < 60000) {
    log("revalidation disabled (REVALIDATE_MS < 60s)");
    return;
  }
  setTimeout(() => revalidateAll().catch((e) => log(`revalidate error: ${e.message}`)), 60000);
  setInterval(() => revalidateAll().catch((e) => log(`revalidate error: ${e.message}`)), REVALIDATE_MS).unref();
  log(`revalidation every ${Math.round(REVALIDATE_MS / 3600000)}h (first run ~60s after start)`);
}

const server = http.createServer(async (req, res) => {
  const ip = clientIp(req);
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname.replace(/\/+$/, "") || "/";

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-tcl-key",
    });
    return res.end();
  }

  if (rateLimited(ip)) return sendJson(res, 429, { ok: false, error: "rate limited" });

  try {
    if (req.method === "POST" && p === "/api/curef") {
      const body = await readBody(req);
      return handleRecord(req, res, body);
    }
    if (req.method === "POST" && p === "/api/revalidate") {
      if (API_KEY && req.headers["x-tcl-key"] !== API_KEY) return sendJson(res, 401, { ok: false, error: "bad or missing key" });
      revalidateAll().catch((e) => log(`revalidate error: ${e.message}`));  // fire-and-forget
      return sendJson(res, 202, { ok: true, started: !revalidating ? false : true, note: "revalidation running in background" });
    }
    if (req.method === "GET" && p === "/api/curefs") {
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "1000", 10) || 1000, 5000);
      const offset = parseInt(url.searchParams.get("offset") || "0", 10) || 0;
      const all = [...store.values()].sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""));
      return sendJson(res, 200, { count: all.length, records: all.slice(offset, offset + limit) });
    }
    if (req.method === "GET" && p === "/api/templates") {
      return sendJson(res, 200, { devices: templatesFeed() });
    }
    if (req.method === "GET" && p === "/api/stats") {
      return sendJson(res, 200, stats());
    }
    if (req.method === "GET" && p === "/healthz") {
      return sendJson(res, 200, { ok: true, records: store.size });
    }
    if (req.method === "GET" && (p === "/" || p === "/about")) {
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" });
      return res.end(aboutPage());
    }
    return sendJson(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: e.message });
  }
});

// ── boot ────────────────────────────────────────────────────────────────────
fs.mkdirSync(DATA_DIR, { recursive: true });
loadStore();
if (!API_KEY) log("WARNING: TCL_CUREF_KEY not set — write endpoint is unauthenticated");

server.listen(PORT, HOST, () => log(`tcl-curef server listening on ${HOST}:${PORT} (data: ${DATA_DIR})`));
scheduleRevalidation();

function shutdown() {
  log("shutting down, flushing…");
  flush();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
