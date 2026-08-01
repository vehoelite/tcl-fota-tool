#!/usr/bin/env node
/**
 * tcl-fota — Firmware update checker & downloader for TCL/REVVL devices
 * 
 * Queries TCL's FOTA (Firmware Over The Air) servers to check for available 
 * updates and retrieve direct download URLs for any TCL-manufactured device.
 * 
 * Supports: TCL, REVVL (T-Mobile), Alcatel, and other TCL-manufactured phones.
 * 
 * Protocol reverse-engineered from com.tcl.fota.system v7.2321.07.14078.141.0
 * Key sources: com/tcl/fota/common/utils/g.java, com/tcl/fota/check/impl/h.java
 * 
 * Zero dependencies — uses only Node.js built-in modules.
 * 
 * Usage:
 *   node tcl-fota.js check --curef PRD-63117-011 --fv AAO0
 *   node tcl-fota.js download --curef PRD-63117-011 --fv AAO0
 *   node tcl-fota.js list
 *   node tcl-fota.js interactive
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const querystring = require('querystring');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execFile } = require('child_process');

// ─── Protocol Constants ─────────────────────────────────────────────────────

/**
 * VK hash suffix — binary-encoded ASCII string appended to params before SHA-1.
 * Decodes to: "How are you get this key word?"
 * 
 * Discovered by decompiling com.tcl.fota.system APK with jadx.
 * Located in: com/tcl/fota/common/utils/g.java method b()
 */
const VK_SUFFIX = 
  "010010000110111101110111001000000110000101110010011001010010000" +
  "001111001011011110111010100100000011001110110010101110100001000" +
  "000111010001101000011010010111001100100000011010110110010101111" +
  "001001000000111011101101111011100100110010000111111";

const SERVERS = {
  master: "master.tctsdc.com",
  china:  "g2master-cn-south.tclclouds.com",
  slaves: [
    "g2master-us-east.tclclouds.com",
    "g2master-us-west.tclclouds.com",
    "g2master-eu-west.tclclouds.com",
    "g2master-ap-south.tclclouds.com",
    "g2master-ap-north.tclclouds.com",
    "g2master-sa-east.tclclouds.com",
  ]
};

const USER_AGENT = "com.tcl.fota.system/7.2321.07.14078.141.0 , Android";

// ─── Known Devices ──────────────────────────────────────────────────────────

const KNOWN_DEVICES = {
  // TCL Branded
  "TCL 30 XE 5G":            { curef: "T776B-2ALGUS12-V" },
  "TCL 30 V 5G":             { curef: "T781S-2ALGUS12-V" },
  "TCL 40 XE":               { curef: "T609DL-2ALGUS12-V" },
  "TCL 30 XL (Tracfone)":    { curef: "T601DL-2AKFUS11-N" },
  "TCL REVVL V+ 5G":         { curef: "T618DL-2ALGUS12-V" },
  "TCL REVVL 6 5G":          { curef: "T608DL-2ALGUS12-V" },
  "TCL REVVL 6 5G (Tracfone)": { curef: "T608DL-2AKFUS11-N" },
  "TCL REVVL 6 Pro 5G":      { curef: "T609DL-2ALGUS12-V" },
  "TCL REVVL 7 5G":          { curef: "T701DL-2ALGUS12-V" },
  "TCL REVVL 7 Pro 5G":      { curef: "T702DL-2ALGUS12-V" },
  "TCL T702Z (Dish/Boost)":  { curef: "T702Z-EARXUS12-V" },
  "TCL NxtPaper 70 Pro (T-Mobile/Metro)": { curef: "T807W-EATBUS12-V" },
  "TCL T614SP (unconfirmed)": { curef: "T614sp-2auhus12" },
  // Alcatel
  "Alcatel Joy Tab 2":       { curef: "9032Z-2ALGUS12-V" },
  // Add more as community discovers them
  // Format: "Device Name": { curef: "CUREF-VALUE" }
};

// ─── Core Protocol Implementation ───────────────────────────────────────────

/**
 * Generate salt: timestamp + 6 random digits
 * Matches: com/tcl/fota/common/utils/g.java method e()
 */
function generateSalt() {
  const ts = Date.now();
  const rand = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
  return `${ts}${rand}`;
}

/**
 * Compute VK verification hash.
 * Matches: com/tcl/fota/common/utils/g.java method b(Map<String, String>)
 *
 * Builds: "key1=val1&key2=val2&...&lastKey=lastVal{VK_SUFFIX}"
 * Then: SHA-1 → lowercase hex
 *
 * IMPORTANT: VK_SUFFIX is appended directly after the last value (no & separator).
 * The binary string is used as-is (literal '0'/'1' characters), NOT decoded to ASCII.
 */
function computeVk(orderedParams) {
  const entries = Object.entries(orderedParams);
  let str = "";
  for (let i = 0; i < entries.length; i++) {
    const [key, value] = entries[i];
    if (i === entries.length - 1) {
      str += `${key}=${value}${VK_SUFFIX}`;
    } else {
      str += `${key}=${value}&`;
    }
  }
  return crypto.createHash("sha1").update(str, "utf-8").digest("hex").toLowerCase();
}

/**
 * Build check_new.php parameters.
 * Matches: com/tcl/fota/check/impl/h.java inner class a (LinkedHashMap)
 * 
 * VK is computed from: {id, salt, curef, fv, type, mode, cltp}
 * Then appended along with post-VK params: {cktp, rtd, chnl, osvs, ckot}
 */
function buildCheckParams(curef, fv, opts = {}) {
  const id = opts.imei || "543212345000000";
  const preVk = {
    id,
    salt: generateSalt(),
    curef,
    fv,
    type: "Firmware",
    mode: String(opts.mode || 2),  // 2=OTA, 4=FULL
    cltp: "10",
  };

  const vk = computeVk(preVk);

  return {
    ...preVk,
    vk,
    cktp: String(opts.cktp || 2),       // 1=auto, 2=manual
    rtd:  String(opts.rtd  || 1),       // 1=not rooted, 2=rooted
    chnl: String(opts.chnl || 2),       // 1=mobile, 2=wifi
    osvs: String(opts.osvs || "15"),
    ckot: "2",
  };
}

/**
 * Build download_request_new.php parameters.
 * Matches: com/tcl/fota/check/impl/h.java inner class b (LinkedHashMap)
 */
function buildDownloadParams(curef, fv, tv, fwId, opts = {}) {
  const id = opts.imei || "543212345000000";
  const preVk = {
    id,
    salt: generateSalt(),
    curef,
    fv,
    tv,
    type: "Firmware",
    fw_id: fwId,
    mode: String(opts.mode || 2),
    cltp: "10",
  };

  const vk = computeVk(preVk);

  const params = {
    ...preVk,
    vk,
    cktp: String(opts.cktp || 2),
    rtd:  String(opts.rtd  || 1),
  };

  // FULL images require foot=1 (inserted after rtd, before chnl, and NOT part of
  // the VK). Without it the server returns a bare S3 key that 404s (NoSuchKey);
  // with it the server returns the resolvable /body/... key. See issue #3.
  // Matches com/tcl/fota/check/impl/h.java: params.put("foot", "1") for FULL.
  if (String(opts.mode || 2) === "4") {
    params.foot = "1";
  }

  params.chnl = String(opts.chnl || 2);
  return params;
}

// ─── HTTP Helpers ───────────────────────────────────────────────────────────

function httpPost(url, params, headers = {}) {
  return new Promise((resolve, reject) => {
    const body = querystring.stringify(params);
    const parsed = new URL(url);
    const mod = parsed.protocol === "https:" ? https : http;

    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": USER_AGENT,
        ...headers,
      },
      timeout: 30000,
    };

    const req = mod.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => {
        const buffer = Buffer.concat(chunks);
        const bodyText = buffer.toString("utf8");
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: bodyText,
          rawBody: buffer,
          contentType: res.headers["content-type"] || "",
        });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
    req.write(body);
    req.end();
  });
}

function extractMultipartPayloads(buffer, contentType = "") {
  if (!contentType.toLowerCase().includes("multipart")) return [buffer];

  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!boundaryMatch) return [buffer];

  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const delimiter = `--${boundary}`;
  const text = buffer.toString("binary");
  const parts = [];

  for (const section of text.split(delimiter)) {
    const cleaned = section.replace(/^\r?\n/, "").replace(/\r?\n$/, "");
    if (!cleaned || cleaned === "--") continue;

    const headerEnd = cleaned.indexOf("\r\n\r\n");
    const payload = headerEnd === -1 ? cleaned : cleaned.slice(headerEnd + 4);
    if (payload && payload.trim() !== "") {
      parts.push(Buffer.from(payload.replace(/\r?\n$/, ""), "binary"));
    }
  }

  return parts.length > 0 ? parts : [buffer];
}

/**
 * Stream a URL to disk. Multipart (207) responses are still small XML/binary
 * wrapper payloads, so those are buffered and unwrapped as before; everything
 * else is piped straight to a write stream so multi-GB FULL-image bodies never
 * sit fully in memory.
 *
 * Supports resume: if `resumeFrom` is given, sends a Range header and appends
 * to the existing file instead of truncating it.
 */
function httpDownload(url, dest, onProgress, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === "https:" ? https : http;
    const resumeFrom = opts.resumeFrom || 0;

    const headers = { "User-Agent": USER_AGENT };
    if (resumeFrom > 0) headers["Range"] = `bytes=${resumeFrom}-`;

    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + (parsed.search || ""),
      method: "GET",
      headers,
      timeout: 30000,
    };

    const req = mod.request(reqOpts, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return httpDownload(res.headers.location, dest, onProgress, opts).then(resolve, reject);
      }

      // Server ignored our Range request (some slaves don't support it) — the
      // caller's on-disk partial data is now stale, so start the file over.
      const gotRange = res.statusCode === 206;
      if (resumeFrom > 0 && !gotRange) {
        fs.truncate(dest, 0, () => {});
      }
      const effectiveResume = gotRange ? resumeFrom : 0;

      if (![200, 206, 207].includes(res.statusCode)) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      const contentType = res.headers["content-type"] || "";
      const isMultipart = res.statusCode === 207 && contentType.toLowerCase().includes("multipart");

      if (isMultipart) {
        // Multipart wrapper payloads are the small XML/JSON metadata case, not
        // the multi-GB body case — buffering here is fine.
        const chunks = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          const payload = Buffer.concat(extractMultipartPayloads(Buffer.concat(chunks), contentType));
          fs.writeFile(dest, payload, (err) => {
            if (err) return reject(err);
            resolve({ size: payload.length });
          });
        });
        res.on("error", reject);
        return;
      }

      const contentLength = parseInt(res.headers["content-length"], 10) || 0;
      const total = gotRange ? contentLength + effectiveResume : contentLength;
      let received = effectiveResume;

      const out = fs.createWriteStream(dest, { flags: effectiveResume > 0 ? "r+" : "w", start: effectiveResume });

      res.on("data", (chunk) => {
        received += chunk.length;
        if (onProgress) onProgress(received, total);
      });

      res.on("error", (err) => {
        out.destroy();
        reject(err);
      });

      out.on("error", reject);
      out.on("finish", () => resolve({ size: received }));

      res.pipe(out);
    });

    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Download timed out")); });
    req.end();
  });
}

/**
 * Download with automatic resume-on-failure retries. Tries up to `maxRetries`
 * times; each retry resumes from the byte offset already on disk (if the
 * server honors Range) instead of restarting the whole transfer.
 */
async function downloadWithRetry(url, dest, onProgress, opts = {}) {
  const maxRetries = opts.maxRetries != null ? opts.maxRetries : 5;
  let lastErr;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const resumeFrom = fs.existsSync(dest) ? fs.statSync(dest).size : 0;
    try {
      return await httpDownload(url, dest, onProgress, { resumeFrom });
    } catch (e) {
      lastErr = e;
      if (attempt < maxRetries) {
        const backoffMs = Math.min(1000 * Math.pow(2, attempt), 15000);
        await new Promise((r) => setTimeout(r, backoffMs));
      }
    }
  }
  throw lastErr;
}

/**
 * SHA-1 a file on disk via streaming (no full-file buffering).
 */
function sha1File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha1");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex").toLowerCase()));
    stream.on("error", reject);
  });
}

// ─── XML Parsing ────────────────────────────────────────────────────────────

function xmlGet(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
  return m ? m[1] : null;
}

function xmlGetAll(xml, tag) {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, "g");
  const results = [];
  let m;
  while ((m = re.exec(xml)) !== null) results.push(m[1]);
  return results;
}

function parseCheckResponse(xml) {
  // A FULL image lists every partition file in <FILESET>; capture them all so a
  // FULL download can fetch each one. OTA responses have a single <FILE>.
  const fileset = [];
  const fileRe = /<FILE>([\s\S]*?)<\/FILE>/g;
  let fm;
  while ((fm = fileRe.exec(xml)) !== null) {
    const block = fm[1];
    fileset.push({
      fileId:   xmlGet(block, "FILE_ID"),
      filename: xmlGet(block, "FILENAME"),
      size:     xmlGet(block, "SIZE"),
      checksum: xmlGet(block, "CHECKSUM"),
      index:    xmlGet(block, "INDEX"),
    });
  }

  return {
    curef:      xmlGet(xml, "CUREF"),
    fv:         xmlGet(xml, "FV"),
    tv:         xmlGet(xml, "TV"),
    svn:        xmlGet(xml, "SVN"),
    fw_id:      xmlGet(xml, "FW_ID"),
    filename:   xmlGet(xml, "FILENAME"),
    filesize:   xmlGet(xml, "SIZE"),
    checksum:   xmlGet(xml, "CHECKSUM"),
    file_id:    xmlGet(xml, "FILE_ID"),
    fileset,
    year:       xmlGet(xml, "year"),
    month:      xmlGet(xml, "month"),
    day:        xmlGet(xml, "day"),
  };
}

function parseDownloadResponse(xml) {
  // Each <FILE> in <FILE_LIST> pairs a FILE_ID with its relative DOWNLOAD_URL.
  // A FULL image is many files (one .mbn per partition); an OTA is usually one.
  const files = [];
  const fileRe = /<FILE>([\s\S]*?)<\/FILE>/g;
  let fm;
  while ((fm = fileRe.exec(xml)) !== null) {
    const block = fm[1];
    files.push({
      fileId:      xmlGet(block, "FILE_ID"),
      downloadUrl: xmlGet(block, "DOWNLOAD_URL"),
      s3Url:       xmlGet(block, "S3_DOWNLOAD_URL"),
    });
  }

  return {
    // First-file fields kept for backward compatibility with existing callers.
    fileId:       xmlGet(xml, "FILE_ID"),
    downloadUrl:  xmlGet(xml, "DOWNLOAD_URL"),
    files,
    slaves:       xmlGetAll(xml, "SLAVE"),
    encSlaves:    xmlGetAll(xml, "ENCRYPT_SLAVE"),
    s3Slaves:     xmlGetAll(xml, "S3_SLAVE"),
  };
}

/**
 * Parse a checksum.php response into per-part SHA-1 hashes.
 * A FULL firmware file is delivered in three parts:
 *   BODY           — served plaintext at https://{slave}/body{downloadUrl}
 *   HEADER         — served encrypted via POST {encslave}/encrypt_header.php
 *   FOOTER         — the plaintext tail; its hash is FOOTER, encrypted form ENCRYPT_FOOTER
 * The final flashable .mbn = decrypt(header) + body + footer.
 */
function parseChecksumResponse(xml) {
  return {
    address:       xmlGet(xml, "ADDRESS"),
    body:          xmlGet(xml, "BODY"),
    footer:        xmlGet(xml, "FOOTER"),
    encryptFooter: xmlGet(xml, "ENCRYPT_FOOTER"),
  };
}

// ─── Main Operations ────────────────────────────────────────────────────────

/**
 * Check for firmware update
 */
async function checkUpdate(curef, fv, opts = {}) {
  const servers = [SERVERS.master, ...SERVERS.slaves];
  const quiet = opts.quiet || false;

  for (const server of servers) {
    const params = buildCheckParams(curef, fv, opts);
    const url = `https://${server}/check_new.php`;

    if (!quiet) process.stdout.write(`  Checking ${server}... `);

    try {
      const res = await httpPost(url, params);

      if ([200, 206, 207].includes(res.status)) {
        if (!quiet) console.log("OK");
        const bodyText = res.body || "";
        const candidateText = (res.contentType || "").toLowerCase().includes("multipart")
          ? (res.rawBody ? res.rawBody.toString("utf8") : bodyText)
          : bodyText;
        const info = parseCheckResponse(candidateText);
        info._server = server;
        info._raw = bodyText;
        return info;
      } else if (res.status === 204) {
        if (!quiet) console.log("no update");
      } else if (res.status === 404) {
        if (!quiet) console.log("not found");
      } else {
        if (!quiet) console.log(`HTTP ${res.status}`);
        // If server says VK is wrong, show it
        if (res.body && res.body.includes("vk")) {
          if (!quiet) console.log(`    Server: ${res.body.substring(0, 200)}`);
        }
      }
    } catch (e) {
      if (!quiet) console.log(`error: ${e.message}`);
    }
  }

  return null;
}

/**
 * Get firmware download URLs
 */
async function getDownloadUrls(curef, fv, tv, fwId, opts = {}) {
  const servers = [SERVERS.master, ...SERVERS.slaves];
  const quiet = opts.quiet || false;

  for (const server of servers) {
    const params = buildDownloadParams(curef, fv, tv, fwId, opts);
    const url = `https://${server}/download_request_new.php`;

    if (!quiet) process.stdout.write(`  Requesting from ${server}... `);

    try {
      const res = await httpPost(url, params);

      if (res.status === 200) {
        if (!quiet) console.log("OK");
        const dl = parseDownloadResponse(res.body);
        dl._server = server;
        dl._raw = res.body;
        return dl;
      } else {
        if (!quiet) console.log(`HTTP ${res.status}`);
      }
    } catch (e) {
      if (!quiet) console.log(`error: ${e.message}`);
    }
  }

  return null;
}

/**
 * Build full download URL list for a file's BODY, one per slave server.
 *
 * The relative path comes straight from the server's DOWNLOAD_URL and is used
 * verbatim. The critical detail is upstream, in buildDownloadParams: sending
 * foot=1 for FULL (mode 4) makes the server return a resolvable /body/... path;
 * without foot the server returns a bare key that 404s (NoSuchKey). See issue #3.
 *
 * @param {object} dlInfo   parsed download response
 * @param {string} [relUrl] specific file's DOWNLOAD_URL (defaults to first file)
 */
function buildFullUrls(dlInfo, relUrl) {
  const rel = relUrl || (dlInfo && dlInfo.downloadUrl);
  if (!dlInfo || !rel) return [];

  const urls = [];
  const servers = dlInfo.slaves.length > 0
    ? dlInfo.slaves
    : dlInfo.encSlaves.length > 0
      ? dlInfo.encSlaves
      : [];

  if (servers.length > 0) {
    for (const s of servers) {
      urls.push(`https://${s}${rel}`);
    }
  } else {
    urls.push(rel);
  }
  return urls;
}

// ─── FULL-image part clients ────────────────────────────────────────────────
//
// A FULL firmware file is delivered in three parts (see parseChecksumResponse):
//   BODY   — plaintext, downloadable directly (this tool can save it verbatim)
//   HEADER — ENCRYPTED, fetched from an encrypt slave; ~4 MiB
//   FOOTER — plaintext tail, bundled inside the encrypted header blob
//
// The final flashable .mbn = decrypt(HEADER) + BODY + FOOTER. Decrypting the
// header requires TCL's proprietary key from the com.tcl.fota APK. This tool
// deliberately does NOT decrypt — it downloads the parts TCL's public API serves
// and leaves the decrypt/assemble step to the device owner. See DECRYPTION below.

// Service credentials used by encrypt_header.php / checksum.php. These are the
// same public service-account values the FOTA client posts (base64-wrapped here
// only to keep them out of plain grep, exactly as the app stores them).
const ENC_CREDS = {
  account:  Buffer.from("VGVsZUV4dFRlc3Q=", "base64").toString("utf8"), // TeleExtTest
  password: Buffer.from("dDA1MjM=", "base64").toString("utf8"),         // t0523
};

/**
 * Fetch the encrypted header blob for a file from an encrypt slave.
 * Returns the raw (still-encrypted) bytes. Expects HTTP 206.
 */
function fetchEncryptedHeader(encSlave, relUrl) {
  return new Promise((resolve, reject) => {
    const body = querystring.stringify({ ...ENC_CREDS, address: relUrl });
    const req = http.request({
      hostname: encSlave,
      path: "/encrypt_header.php",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": USER_AGENT,
      },
      timeout: 30000,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => {
        if (res.statusCode !== 206 && res.statusCode !== 200) {
          return reject(new Error(`encrypt_header HTTP ${res.statusCode}`));
        }
        resolve(Buffer.concat(chunks));
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("encrypt_header timed out")); });
    req.write(body);
    req.end();
  });
}

/**
 * Query checksum.php for a file's per-part SHA-1s (BODY / FOOTER / ENCRYPT_FOOTER).
 */
function fetchPartChecksums(encSlave, relUrl) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ [relUrl]: relUrl });
    const body = querystring.stringify({ ...ENC_CREDS, address: payload });
    const req = http.request({
      hostname: encSlave,
      path: "/checksum.php",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": USER_AGENT,
      },
      timeout: 30000,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => {
        if (res.statusCode !== 200) return reject(new Error(`checksum HTTP ${res.statusCode}`));
        resolve(parseChecksumResponse(Buffer.concat(chunks).toString("utf8")));
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("checksum timed out")); });
    req.write(body);
    req.end();
  });
}

// ─── Progress Bar ───────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + " " + sizes[i];
}

function drawProgress(received, total) {
  const cols = process.stdout.columns || 80;
  const pct = total > 0 ? (received / total) : 0;
  const pctStr = total > 0 ? `${(pct * 100).toFixed(1)}%` : "???%";
  const sizeStr = `${formatBytes(received)}${total > 0 ? "/" + formatBytes(total) : ""}`;
  const info = ` ${pctStr} ${sizeStr} `;
  const barWidth = Math.max(10, cols - info.length - 4);
  const filled = Math.round(barWidth * pct);
  const bar = "█".repeat(filled) + "░".repeat(barWidth - filled);
  process.stdout.write(`\r  [${bar}]${info}`);
}

// ─── CLI Interface ──────────────────────────────────────────────────────────

function printBanner() {
  console.log("");
  console.log("  ╔════════════════════════════════════════════════════╗");
  console.log("  ║           tcl-fota — TCL Firmware Tool            ║");
  console.log("  ║    Firmware checker & downloader for TCL/REVVL    ║");
  console.log("  ╚════════════════════════════════════════════════════╝");
  console.log("");
}

function printUsage() {
  printBanner();
  console.log("  USAGE:");
  console.log("    node tcl-fota.js <command> [options]");
  console.log("");
  console.log("  COMMANDS:");
  console.log("    check      Check for available firmware update");
  console.log("    download   Check + download firmware file");
  console.log("    list       Show known device CUREFs");
  console.log("    interactive  Guided mode (no arguments needed)");
  console.log("");
  console.log("  OPTIONS:");
  console.log("    --curef <val>   Device CUREF identifier (required for check/download)");
  console.log("    --fv <val>      Current firmware version (required for check/download)");
  console.log("    --mode <2|4>    2=OTA incremental, 4=FULL image (default: 2)");
  console.log("    --osvs <val>    Android version to report (default: 15)");
  console.log("    --imei <val>    Device IMEI (default: dummy value)");
  console.log("    --out <dir>     Output directory for downloads (default: current dir)");
  console.log("");
  console.log("  EXAMPLES:");
  console.log("    node tcl-fota.js check --curef T702Z-EARXUS12-V --fv 9LBHZDH0");
  console.log("    node tcl-fota.js download --curef T702Z-EARXUS12-V --fv 9LBHZDH0");
  console.log("    node tcl-fota.js interactive");
  console.log("    node tcl-fota.js list");
  console.log("");
  console.log("  HOW TO FIND YOUR CUREF AND FV:");
  console.log("    Easiest: run `node tcl-fota.js interactive` with your phone plugged");
  console.log("    in over USB (debugging enabled) — it reads the CUREF for you.");
  console.log("    On your TCL/REVVL phone:");
  console.log("      Settings → About Phone → look for 'CUREF' and firmware version");
  console.log("    Or via ADB:");
  console.log("      adb shell getprop ro.tct.curef");
  console.log("");
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--") && i + 1 < argv.length) {
      args[argv[i].slice(2)] = argv[i + 1];
      i++;
    } else if (!argv[i].startsWith("--")) {
      args._command = argv[i];
    }
  }
  return args;
}

/**
 * Ask a question and resolve with the trimmed answer. If stdin has already
 * ended (e.g. piped/non-interactive input exhausted, or the terminal session
 * dropping), `rl.question()` throws synchronously rather than calling back —
 * catch that and resolve to "" instead of crashing. Callers already treat an
 * empty answer as "use the default" or "nothing provided", so this degrades
 * the same way a blank Enter press would.
 */
function askQuestion(rl, prompt) {
  return new Promise((resolve) => {
    if (rl.closed) return resolve("");
    let settled = false;
    const onClose = () => {
      if (!settled) { settled = true; resolve(""); }
    };
    rl.once("close", onClose);
    try {
      rl.question(prompt, (answer) => {
        if (settled) return;
        settled = true;
        rl.removeListener("close", onClose);
        resolve(answer.trim());
      });
    } catch (e) {
      settled = true;
      resolve("");
    }
  });
}

async function runCheck(curef, fv, opts = {}) {
  console.log(`\n  Device:   ${curef}`);
  console.log(`  Current:  ${fv}`);
  console.log(`  Mode:     ${opts.mode === 4 ? "FULL" : "OTA"}\n`);

  console.log("  Checking for updates...");
  const info = await checkUpdate(curef, fv, opts);

  if (!info) {
    console.log("\n  No update found. The firmware version may already be current,");
    console.log("  or the CUREF/FV combination may be incorrect.\n");
    return null;
  }

  console.log("");
  console.log("  ┌─────────────── Update Available ───────────────┐");
  console.log(`  │  CUREF:    ${(info.curef || "?").padEnd(37)}│`);
  console.log(`  │  From:     ${(info.fv || "?").padEnd(37)}│`);
  console.log(`  │  To:       ${(info.tv || "?").padEnd(37)}│`);
  console.log(`  │  FW ID:    ${(info.fw_id || "?").padEnd(37)}│`);
  console.log(`  │  File:     ${(info.filename || "?").padEnd(37)}│`);
  console.log(`  │  Size:     ${formatBytes(parseInt(info.filesize || "0")).padEnd(37)}│`);
  console.log(`  │  SHA-1:    ${(info.checksum || "?").padEnd(37)}│`);
  if (info.year) {
    const date = `${info.year}-${(info.month || "").padStart(2, "0")}-${(info.day || "").padStart(2, "0")}`;
    console.log(`  │  Released: ${date.padEnd(37)}│`);
  }
  console.log("  └───────────────────────────────────────────────┘");

  return info;
}

async function runDownload(curef, fv, opts = {}) {
  const info = await runCheck(curef, fv, opts);
  if (!info || !info.fw_id) return;

  console.log("\n  Requesting download URLs...");
  const dlInfo = await getDownloadUrls(curef, fv, info.tv, info.fw_id, opts);

  if (!dlInfo || !dlInfo.downloadUrl) {
    console.log("\n  Could not retrieve download URL.\n");
    return;
  }

  const outDir = opts.out || process.cwd();
  ensureDir(outDir);

  if (String(opts.mode || 2) === "4") {
    await downloadFullImage(curef, info, dlInfo, outDir);
  } else {
    await downloadOtaFile(curef, info, dlInfo, outDir, opts);
  }
}

/**
 * Same flow as runDownload(), but for the GUI: emits one JSON object per
 * line to stdout instead of formatted console output, so a caller can parse
 * progress without scraping human-readable text. OTA (mode 2) only for now —
 * FULL mode's many-file/multi-part flow doesn't fit this simple event model
 * yet and stays a CLI-only feature until there's a case for a GUI FULL flow.
 */
function emitJson(obj) {
  console.log(JSON.stringify(obj));
}

async function runDownloadJson(curef, fv, opts = {}) {
  if (String(opts.mode || 2) === "4") {
    emitJson({ type: "error", message: "FULL mode isn't supported via the GUI yet — use the CLI (`node tcl-fota.js download --mode 4`)." });
    return;
  }

  emitJson({ type: "checking" });
  const info = await checkUpdate(curef, fv, { ...opts, quiet: true });
  if (!info || !info.fw_id) {
    emitJson({ type: "no-update" });
    return;
  }
  delete info._raw;
  emitJson({ type: "update-found", info });

  emitJson({ type: "requesting-url" });
  const dlInfo = await getDownloadUrls(curef, fv, info.tv, info.fw_id, opts);
  if (!dlInfo || !dlInfo.downloadUrl) {
    emitJson({ type: "error", message: "Could not retrieve download URL." });
    return;
  }

  const outDir = opts.out || process.cwd();
  ensureDir(outDir);

  const urls = buildFullUrls(dlInfo, dlInfo.downloadUrl);
  const preferred = urls.find((u) => u.includes("us-east")) || urls[0];
  const filename = info.filename || `firmware_${curef}_${info.tv}.zip`;
  const dest = path.join(outDir, filename);

  emitJson({ type: "downloading", filename, dest, size: parseInt(info.filesize || "0") });

  const startTime = Date.now();
  let lastEmit = 0;
  try {
    const result = await downloadWithRetry(preferred, dest, (received, total) => {
      const now = Date.now();
      if (now - lastEmit < 200 && received !== total) return; // throttle to ~5/sec
      lastEmit = now;
      emitJson({ type: "progress", received, total });
    });

    const elapsed = (Date.now() - startTime) / 1000;
    let verified = null;
    if (info.checksum) {
      emitJson({ type: "verifying" });
      const actual = await sha1File(dest);
      verified = actual === info.checksum.toLowerCase();
    }

    emitJson({ type: "done", dest, size: result.size, elapsedSeconds: elapsed, verified });
  } catch (e) {
    emitJson({ type: "error", message: e.message, dest, resumable: true });
  }
}

/**
 * OTA (mode 2): a single delta file, served plaintext at its DOWNLOAD_URL.
 */
async function downloadOtaFile(curef, info, dlInfo, outDir, opts) {
  const urls = buildFullUrls(dlInfo, dlInfo.downloadUrl);
  console.log("\n  Download URLs:");
  for (const url of urls) console.log(`    ${url}`);

  const preferred = urls.find((u) => u.includes("us-east")) || urls[0];
  const filename = info.filename || `firmware_${curef}_${info.tv}.zip`;
  const dest = path.join(outDir, filename);

  console.log(`\n  Downloading to: ${dest}`);
  console.log(`  Size: ${formatBytes(parseInt(info.filesize || "0"))}\n`);

  const startTime = Date.now();
  try {
    const result = await downloadWithRetry(preferred, dest, drawProgress);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const speed = formatBytes(result.size / (elapsed || 1));
    console.log(`\n\n  Download complete!`);
    console.log(`  File:     ${dest}`);
    console.log(`  Size:     ${formatBytes(result.size)}`);
    console.log(`  Time:     ${elapsed}s (${speed}/s)`);

    if (info.checksum) {
      process.stdout.write(`  Verifying SHA-1... `);
      const actual = await sha1File(dest);
      if (actual === info.checksum.toLowerCase()) {
        console.log("OK");
      } else {
        console.log("MISMATCH");
        console.log(`    Expected: ${info.checksum}`);
        console.log(`    Actual:   ${actual}`);
        console.log(`    The file may be corrupt or incomplete — try downloading again.`);
      }
    }
    console.log("");
  } catch (e) {
    console.log(`\n\n  Download failed: ${e.message}`);
    console.log(`  You can manually download from:\n    ${preferred}\n`);
    console.log(`  Run the same command again to resume from where it left off.\n`);
  }
}

/**
 * FULL image (mode 4): many partition files. Each file is delivered in parts:
 *   BODY   (plaintext)  — downloaded verbatim
 *   HEADER (encrypted)  — downloaded verbatim (still encrypted)
 *   FOOTER (plaintext)  — bundled inside the encrypted header blob
 *
 * We save the plaintext BODY plus the encrypted HEADER for every file, and write
 * a manifest. Reassembling a flashable .mbn additionally requires DECRYPTING the
 * header with TCL's key (see the DECRYPTION note printed at the end) — this tool
 * does not perform that step.
 */
async function downloadFullImage(curef, info, dlInfo, outDir) {
  const files = dlInfo.files && dlInfo.files.length ? dlInfo.files : [{
    fileId: dlInfo.fileId, downloadUrl: dlInfo.downloadUrl,
  }];

  // Map FILE_ID -> filename/checksum from the check fileset for friendly names.
  const byId = {};
  for (const f of (info.fileset || [])) byId[f.fileId] = f;

  const fwDir = path.join(outDir, `${curef}_${info.tv}_FULL`);
  ensureDir(fwDir);

  const slaves = dlInfo.slaves || [];
  const encSlaves = dlInfo.encSlaves || [];
  const bodyHosts = [slaves.find((s) => s.includes("us-east")), ...slaves].filter(Boolean);
  const encHosts = encSlaves.filter(Boolean);

  console.log(`\n  FULL image: ${files.length} file(s) → ${fwDir}`);
  console.log(`  Body servers:   ${bodyHosts.join(", ") || "?"}`);
  console.log(`  Header servers: ${encHosts.join(", ") || "(none advertised)"}\n`);

  const manifest = {
    curef, tv: info.tv, fw_id: info.fw_id, fetched_at: new Date().toISOString(),
    note: "Final flashable .mbn per file = decrypt(header) + body + footer. " +
          "Header is TCL-encrypted; this tool does not decrypt it.",
    files: [],
  };

  let idx = 0;
  for (const f of files) {
    idx++;
    const meta = byId[f.fileId] || {};
    const baseName = meta.filename || `file_${f.fileId}`;
    const rel = f.downloadUrl;
    process.stdout.write(`  [${idx}/${files.length}] ${baseName} ... `);

    const entry = { fileId: f.fileId, filename: baseName, index: meta.index, downloadUrl: rel };

    // BODY (plaintext). With foot=1 the server's DOWNLOAD_URL is already the
    // /body-prefixed path, so use it verbatim (do not add another /body).
    // Try each advertised body server in turn — a single host being down
    // shouldn't fail the whole partition.
    const bodyDest = path.join(fwDir, `${baseName}.body`);
    let bodyErr = null;
    for (const host of bodyHosts.length ? bodyHosts : [null]) {
      if (!host) { bodyErr = new Error("no body server advertised"); break; }
      try {
        const bodyUrl = `https://${host}${rel}`;
        const r = await downloadWithRetry(bodyUrl, bodyDest, null);
        entry.body = { file: `${baseName}.body`, size: r.size };
        bodyErr = null;
        break;
      } catch (e) {
        bodyErr = e;
      }
    }
    if (bodyErr) entry.bodyError = bodyErr.message;

    // Per-part checksums (try each encrypt slave until one answers).
    for (const host of encHosts) {
      try {
        entry.checksums = await fetchPartChecksums(host, rel);
        break;
      } catch (e) {
        entry.checksumError = e.message;
      }
    }

    // Verify the downloaded BODY against the authoritative checksum, if we got both.
    if (entry.body && entry.checksums && entry.checksums.body) {
      try {
        const actual = await sha1File(bodyDest);
        entry.bodyVerified = actual === entry.checksums.body.toLowerCase();
        entry.bodyActualSha1 = actual;
      } catch (e) {
        entry.bodyVerifyError = e.message;
      }
    }

    // HEADER (encrypted), if an encrypt slave is available. Kept as-is (still
    // encrypted) — this tool does not decrypt it.
    for (const host of encHosts) {
      try {
        const header = await fetchEncryptedHeader(host, rel);
        const headerDest = path.join(fwDir, `${baseName}.header.enc`);
        fs.writeFileSync(headerDest, header);
        entry.encryptedHeader = { file: `${baseName}.header.enc`, size: header.length };
        break;
      } catch (e) {
        entry.headerError = e.message;
      }
    }

    manifest.files.push(entry);
    let status;
    if (entry.bodyError) status = `body failed (${entry.bodyError})`;
    else if (entry.bodyVerified === false) status = "body CHECKSUM MISMATCH";
    else if (entry.bodyVerified === true) status = "ok (verified)";
    else status = "ok (unverified)";
    console.log(status);
  }

  fs.writeFileSync(path.join(fwDir, "manifest.json"), JSON.stringify(manifest, null, 2));

  const bodies = manifest.files.filter((f) => f.body).length;
  const headers = manifest.files.filter((f) => f.encryptedHeader).length;
  const verified = manifest.files.filter((f) => f.bodyVerified === true).length;
  const mismatched = manifest.files.filter((f) => f.bodyVerified === false).length;
  console.log(`\n  Saved ${bodies} body file(s) and ${headers} encrypted header(s).`);
  console.log(`  Checksum: ${verified} verified, ${mismatched} mismatched, ${bodies - verified - mismatched} unverified.`);
  if (mismatched > 0) {
    console.log(`  WARNING: ${mismatched} file(s) failed checksum verification — re-run to re-download them.`);
  }
  console.log(`  Manifest: ${path.join(fwDir, "manifest.json")}`);
  console.log("");
  console.log("  ── DECRYPTION (not performed by this tool) ─────────────────────");
  console.log("  Each partition's flashable .mbn is:");
  console.log("      decrypt(<name>.header.enc)  +  <name>.body  +  footer");
  console.log("  The header is encrypted with TCL's key from the com.tcl.fota");
  console.log("  APK. The plaintext BODY (checksum-valid on its own) and the");
  console.log("  encrypted HEADER are provided so a device owner can decrypt and");
  console.log("  assemble locally. checksums.BODY/FOOTER in manifest.json are the");
  console.log("  authoritative per-part SHA-1s to verify against.");
  console.log("");
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ─── ADB Auto-Detection ─────────────────────────────────────────────────────
//
// Most non-technical users have no idea what a CUREF or FV is, let alone how
// to run `adb shell getprop`. If a phone is already plugged in with USB
// debugging on, we can just read those values for them. Falls back to manual
// entry (with the same instructions as before) if adb isn't available or no
// device is authorized — this never blocks the existing flow.

function findAdbPath() {
  const bundled = path.join(__dirname, "platform-tools", process.platform === "win32" ? "adb.exe" : "adb");
  if (fs.existsSync(bundled)) return bundled;
  return "adb"; // fall back to PATH
}

function runAdb(args, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    execFile(findAdbPath(), args, { timeout: timeoutMs }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr && stderr.trim() ? stderr.trim() : err.message));
      resolve(stdout.trim());
    });
  });
}

/**
 * Return a list of connected, authorized device serials (skips "unauthorized"
 * / "offline" entries from `adb devices`).
 */
async function listAdbDevices() {
  let out;
  try {
    out = await runAdb(["devices"]);
  } catch (e) {
    return { available: false, reason: e.message, devices: [] };
  }

  const devices = out.split("\n").slice(1)
    .map((line) => line.trim())
    .filter((line) => line && line.endsWith("\tdevice"))
    .map((line) => line.split("\t")[0]);

  return { available: true, devices };
}

/**
 * Read CUREF off a connected device via `adb shell getprop`.
 *
 * Verified live against real hardware: `ro.tct.curef` is the prop that
 * actually holds it (e.g. T702Z, T601DL, T608DL all confirmed) — an earlier
 * version of this tool queried `ro.boot.hardware.curef`, which does not
 * exist on any tested device and always returned empty. FV has no confirmed
 * prop name yet (candidates checked and ruled out: ro.build.fota.version,
 * ro.tct.fv, ro.tct.software.version, ro.build.fingerprint — none match the
 * FV format shown in Settings/the FOTA app), so it stays manual-entry-only
 * until that's pinned down from the FOTA APK.
 */
async function detectDeviceProps(serial) {
  const args = (extra) => serial ? ["-s", serial, ...extra] : extra;

  const curefRaw = await runAdb(args(["shell", "getprop", "ro.tct.curef"])).catch(() => "");

  return {
    curef: curefRaw && curefRaw.trim() ? curefRaw.trim() : null,
    fv: null,
  };
}

async function runList() {
  printBanner();
  console.log("  Known TCL/REVVL Device CUREFs:");
  console.log("  ─────────────────────────────────────────────");
  
  const maxName = Math.max(...Object.keys(KNOWN_DEVICES).map((n) => n.length));
  for (const [name, info] of Object.entries(KNOWN_DEVICES)) {
    console.log(`  ${name.padEnd(maxName + 2)} ${info.curef}`);
  }

  console.log("");
  console.log("  Don't see yours? Find it with:");
  console.log("    adb shell getprop ro.tct.curef");
  console.log("  Or check Settings → About Phone on your device.");
  console.log("");
  console.log("  Submit new CUREFs at: https://github.com/vehoelite/tcl-fota-tool/issues");
  console.log("");
}

/**
 * Try to fill in CUREF/FV automatically from a plugged-in phone. Returns
 * { curef, fv } (either may be null) or null if adb/a device isn't available
 * at all — callers should fall back to the manual picker/prompts in that case.
 * Never throws; this is a convenience path, not a requirement.
 */
async function tryAutoDetect(rl) {
  console.log("  Looking for a connected phone (USB, with USB debugging on)...");
  const status = await listAdbDevices();

  if (!status.available) {
    console.log("  (Skipping auto-detect — adb isn't available on this computer.)\n");
    return null;
  }
  if (status.devices.length === 0) {
    console.log("  No connected/authorized device found.");
    console.log("  Tip: plug in your phone with a USB cable, then on the phone tap");
    console.log("  \"Allow USB debugging\" if a popup appears. If you don't see that");
    console.log("  popup, enable Developer Options first: Settings → About Phone →");
    console.log("  tap \"Build number\" 7 times, then Settings → System → Developer");
    console.log("  options → turn on \"USB debugging\".\n");
    return null;
  }

  let serial = status.devices[0];
  if (status.devices.length > 1) {
    console.log(`  Found ${status.devices.length} devices connected:`);
    status.devices.forEach((d, i) => console.log(`    ${i + 1}. ${d}`));
    const pick = await askQuestion(rl, "  Which one is your phone? [1]: ");
    const n = parseInt(pick);
    if (n >= 1 && n <= status.devices.length) serial = status.devices[n - 1];
  }

  console.log(`  Found a phone (${serial}). Reading its device info...`);
  const props = await detectDeviceProps(serial);

  if (props.curef) {
    console.log(`    Device model (CUREF): ${props.curef}`);
    console.log(`    (Firmware version isn't auto-detectable yet — you'll be asked for it next.)`);
  } else {
    console.log("  Couldn't read the device model from this phone (it may not be a");
    console.log("  TCL/REVVL device, or USB debugging isn't fully authorized).\n");
    return null;
  }

  console.log("");
  return props;
}

async function runInteractive() {
  printBanner();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    let curef = null;
    let fv = null;

    const useAuto = await askQuestion(
      rl,
      "  Do you have your phone plugged into this computer with a USB cable? (Y/n): "
    );

    if (useAuto.toLowerCase() !== "n") {
      const detected = await tryAutoDetect(rl);
      if (detected) {
        curef = detected.curef;
        fv = detected.fv;
      }
    }

    // Fall back to the known-device picker for whatever auto-detect didn't find.
    if (!curef) {
      console.log("  Known devices:");
      const names = Object.keys(KNOWN_DEVICES);
      names.forEach((name, i) => {
        console.log(`    ${i + 1}. ${name} (${KNOWN_DEVICES[name].curef})`);
      });
      console.log(`    ${names.length + 1}. Enter custom CUREF`);
      console.log("");

      const choice = await askQuestion(rl, "  Select your device [number] or press Enter for custom: ");
      const choiceNum = parseInt(choice);
      if (choiceNum >= 1 && choiceNum <= names.length) {
        curef = KNOWN_DEVICES[names[choiceNum - 1]].curef;
        console.log(`\n  Selected: ${names[choiceNum - 1]} → ${curef}`);
      } else {
        curef = await askQuestion(rl, "  Enter CUREF (see Settings → About Phone, or ADB): ");
      }
    }

    if (!curef) {
      console.log("  No device selected. Exiting.\n");
      rl.close();
      return;
    }

    if (!fv) {
      fv = await askQuestion(rl, "  Enter your phone's current firmware version (FV): ");
    }
    if (!fv) {
      console.log("  No firmware version provided. Exiting.\n");
      rl.close();
      return;
    }

    console.log("");
    console.log("  Two kinds of update:");
    console.log("    OTA  — a small patch on top of what's already installed (faster,");
    console.log("           works if you're just a version or two behind)");
    console.log("    FULL — the entire firmware image (much larger, needed if OTA isn't");
    console.log("           offered, or you're recovering a device)");
    const modeStr = await askQuestion(rl, "  Which do you want — OTA or FULL? [OTA]: ");
    const mode = /^f/i.test(modeStr.trim()) || modeStr.trim() === "4" ? 4 : 2;

    console.log("");
    const action = await askQuestion(rl, "  (C)heck for an update only, or (D)ownload it? [C]: ");
    rl.close();

    if (action.toLowerCase() === "d") {
      await runDownload(curef, fv, { mode });
    } else {
      const info = await runCheck(curef, fv, { mode });
      if (info && info.fw_id) {
        console.log("\n  To download, run:");
        console.log(`    node tcl-fota.js download --curef ${curef} --fv ${fv}${mode === 4 ? " --mode 4" : ""}\n`);
        console.log("  Or just run `node tcl-fota.js interactive` again and choose Download.\n");
      }
    }
  } catch (e) {
    rl.close();
    throw e;
  }
}

// ─── Entry Point ────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._command;

  switch (command) {
    case "check": {
      if (!args.curef || !args.fv) {
        console.error("\n  Error: --curef and --fv are required for check.\n");
        printUsage();
        process.exit(1);
      }
      printBanner();
      await runCheck(args.curef, args.fv, { mode: parseInt(args.mode) || 2, osvs: args.osvs });
      break;
    }

    case "download": {
      if (!args.curef || !args.fv) {
        console.error("\n  Error: --curef and --fv are required for download.\n");
        printUsage();
        process.exit(1);
      }
      printBanner();
      await runDownload(args.curef, args.fv, {
        mode: parseInt(args.mode) || 2,
        osvs: args.osvs,
        out: args.out,
      });
      break;
    }

    case "list":
      await runList();
      break;

    case "interactive":
    case "i":
      await runInteractive();
      break;

    // ── Machine-readable commands ────────────────────────────────────────
    // Used by the GUI (gui/) so it never has to parse the human-formatted
    // console output above. Each prints exactly one JSON object (or, for
    // download-json, a stream of newline-delimited JSON progress events)
    // and nothing else — no banners, no console.log noise.

    case "list-json": {
      const devices = Object.entries(KNOWN_DEVICES).map(([name, info]) => ({
        name,
        curef: info.curef,
      }));
      console.log(JSON.stringify({ devices }));
      break;
    }

    case "devices-json": {
      const status = await listAdbDevices();
      const devices = [];
      if (status.available) {
        for (const serial of status.devices) {
          const props = await detectDeviceProps(serial);
          devices.push({ serial, ...props });
        }
      }
      console.log(JSON.stringify({ adbAvailable: status.available, devices }));
      break;
    }

    case "check-json": {
      if (!args.curef || !args.fv) {
        console.log(JSON.stringify({ error: "curef and fv are required" }));
        process.exit(1);
      }
      const info = await checkUpdate(args.curef, args.fv, {
        mode: parseInt(args.mode) || 2,
        osvs: args.osvs,
        quiet: true,
      });
      // Drop the raw XML — it includes a multi-language description CDATA
      // blob for every locale TCL supports, easily 50x the size of the
      // fields the GUI actually needs.
      if (info) delete info._raw;
      console.log(JSON.stringify({ info }));
      break;
    }

    case "download-json": {
      if (!args.curef || !args.fv) {
        console.log(JSON.stringify({ type: "error", message: "curef and fv are required" }));
        process.exit(1);
      }
      await runDownloadJson(args.curef, args.fv, {
        mode: parseInt(args.mode) || 2,
        osvs: args.osvs,
        out: args.out,
      });
      break;
    }

    default:
      // If no command but has curef+fv, assume check
      if (args.curef && args.fv) {
        printBanner();
        await runCheck(args.curef, args.fv, { mode: parseInt(args.mode) || 2, osvs: args.osvs });
      } else {
        printUsage();
      }
      break;
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`\n  Fatal error: ${err.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  httpDownload,
  downloadWithRetry,
  sha1File,
  httpPost,
  checkUpdate,
  getDownloadUrls,
  buildCheckParams,
  buildDownloadParams,
  parseCheckResponse,
  parseDownloadResponse,
  parseChecksumResponse,
  buildFullUrls,
  fetchEncryptedHeader,
  fetchPartChecksums,
  findAdbPath,
  listAdbDevices,
  detectDeviceProps,
};
