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

function httpDownload(url, dest, onProgress) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === "https:" ? https : http;

    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + (parsed.search || ""),
      method: "GET",
      headers: { "User-Agent": USER_AGENT },
      timeout: 30000,
    };

    const req = mod.request(opts, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpDownload(res.headers.location, dest, onProgress).then(resolve, reject);
      }
      if (![200, 206, 207].includes(res.statusCode)) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      const total = parseInt(res.headers["content-length"], 10) || 0;
      const chunks = [];
      let received = 0;

      res.on("data", (chunk) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(buffer);
        received += buffer.length;
        if (onProgress) onProgress(received, total);
      });

      res.on("end", () => {
        const payload = res.statusCode === 207 && (res.headers["content-type"] || "").toLowerCase().includes("multipart")
          ? Buffer.concat(extractMultipartPayloads(Buffer.concat(chunks), res.headers["content-type"] || ""))
          : Buffer.concat(chunks);

        fs.writeFile(dest, payload, (err) => {
          if (err) return reject(err);
          resolve({ size: payload.length });
        });
      });

      res.on("error", (err) => {
        reject(err);
      });
    });

    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Download timed out")); });
    req.end();
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
  console.log("    On your TCL/REVVL phone:");
  console.log("      Settings → About Phone → look for 'CUREF' and firmware version");
  console.log("    Or via ADB:");
  console.log("      adb shell getprop ro.boot.hardware.curef");
  console.log("      adb shell getprop ro.build.fota.version");
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

function askQuestion(rl, prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => resolve(answer.trim()));
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
    const result = await httpDownload(preferred, dest, drawProgress);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const speed = formatBytes(result.size / (elapsed || 1));
    console.log(`\n\n  Download complete!`);
    console.log(`  File:     ${dest}`);
    console.log(`  Size:     ${formatBytes(result.size)}`);
    console.log(`  Time:     ${elapsed}s (${speed}/s)`);
    console.log(`  Checksum: ${info.checksum}`);
    console.log(`\n  Verify with: sha1sum "${filename}"\n`);
  } catch (e) {
    console.log(`\n\n  Download failed: ${e.message}`);
    console.log(`  You can manually download from:\n    ${preferred}\n`);
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
  const bodyHost = slaves.find((s) => s.includes("us-east")) || slaves[0];
  const encHost = encSlaves.find((s) => s) || null;

  console.log(`\n  FULL image: ${files.length} file(s) → ${fwDir}`);
  console.log(`  Body server:   ${bodyHost || "?"}`);
  console.log(`  Header server: ${encHost || "(none advertised)"}\n`);

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
    try {
      const bodyUrl = `https://${bodyHost}${rel}`;
      const bodyDest = path.join(fwDir, `${baseName}.body`);
      const r = await httpDownload(bodyUrl, bodyDest, null);
      entry.body = { file: `${baseName}.body`, size: r.size };
    } catch (e) {
      entry.bodyError = e.message;
    }

    // HEADER (encrypted) + per-part checksums, if an encrypt slave is available.
    if (encHost) {
      try {
        const header = await fetchEncryptedHeader(encHost, rel);
        const headerDest = path.join(fwDir, `${baseName}.header.enc`);
        fs.writeFileSync(headerDest, header);
        entry.encryptedHeader = { file: `${baseName}.header.enc`, size: header.length };
      } catch (e) {
        entry.headerError = e.message;
      }
      try {
        const sums = await fetchPartChecksums(encHost, rel);
        entry.checksums = sums;
      } catch (e) {
        entry.checksumError = e.message;
      }
    }

    manifest.files.push(entry);
    console.log(entry.bodyError ? `body failed (${entry.bodyError})` : "ok");
  }

  fs.writeFileSync(path.join(fwDir, "manifest.json"), JSON.stringify(manifest, null, 2));

  const bodies = manifest.files.filter((f) => f.body).length;
  const headers = manifest.files.filter((f) => f.encryptedHeader).length;
  console.log(`\n  Saved ${bodies} body file(s) and ${headers} encrypted header(s).`);
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
  console.log("    adb shell getprop ro.boot.hardware.curef");
  console.log("  Or check Settings → About Phone on your device.");
  console.log("");
  console.log("  Submit new CUREFs at: https://github.com/vehoelite/tcl-fota-tool/issues");
  console.log("");
}

async function runInteractive() {
  printBanner();
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    // Show known devices
    console.log("  Known devices:");
    const names = Object.keys(KNOWN_DEVICES);
    names.forEach((name, i) => {
      console.log(`    ${i + 1}. ${name} (${KNOWN_DEVICES[name].curef})`);
    });
    console.log(`    ${names.length + 1}. Enter custom CUREF`);
    console.log("");

    const choice = await askQuestion(rl, "  Select device [number] or press Enter for custom: ");
    let curef, fv;

    const choiceNum = parseInt(choice);
    if (choiceNum >= 1 && choiceNum <= names.length) {
      curef = KNOWN_DEVICES[names[choiceNum - 1]].curef;
      console.log(`\n  Selected: ${names[choiceNum - 1]} → ${curef}`);
    } else {
      curef = await askQuestion(rl, "  Enter CUREF: ");
    }

    if (!curef) {
      console.log("  No CUREF provided. Exiting.\n");
      rl.close();
      return;
    }

    fv = await askQuestion(rl, "  Enter current firmware version (FV): ");
    if (!fv) {
      console.log("  No FV provided. Exiting.\n");
      rl.close();
      return;
    }

    const modeStr = await askQuestion(rl, "  Update mode — OTA (2) or FULL (4)? [2]: ");
    const mode = modeStr === "4" ? 4 : 2;

    console.log("");
    const action = await askQuestion(rl, "  (C)heck only or (D)ownload? [C]: ");
    rl.close();

    if (action.toLowerCase() === "d") {
      await runDownload(curef, fv, { mode });
    } else {
      const info = await runCheck(curef, fv, { mode });
      if (info && info.fw_id) {
        console.log("\n  To download, run:");
        console.log(`    node tcl-fota.js download --curef ${curef} --fv ${fv}\n`);
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
};
