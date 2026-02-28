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
  "TCL REVVL V+ 5G":         { curef: "T618DL-2ALGUS12-V" },
  "TCL REVVL 6 5G":          { curef: "T608DL-2ALGUS12-V" },
  "TCL REVVL 6 Pro 5G":      { curef: "T609DL-2ALGUS12-V" },
  "TCL REVVL 7 5G":          { curef: "T701DL-2ALGUS12-V" },
  "TCL REVVL 7 Pro 5G":      { curef: "T702DL-2ALGUS12-V" },
  "TCL T702Z (Dish/Boost)":  { curef: "T702Z-EARXUS12-V" },
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
    osvs: String(opts.osvs || "14"),
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

  return {
    ...preVk,
    vk,
    cktp: String(opts.cktp || 2),
    rtd:  String(opts.rtd  || 1),
    chnl: String(opts.chnl || 2),
  };
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
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
    req.write(body);
    req.end();
  });
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
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      const total = parseInt(res.headers["content-length"], 10) || 0;
      let received = 0;
      const file = fs.createWriteStream(dest);

      res.on("data", (chunk) => {
        received += chunk.length;
        file.write(chunk);
        if (onProgress) onProgress(received, total);
      });

      res.on("end", () => {
        file.end();
        resolve({ size: received });
      });

      res.on("error", (err) => {
        file.destroy();
        fs.unlinkSync(dest);
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
    year:       xmlGet(xml, "year"),
    month:      xmlGet(xml, "month"),
    day:        xmlGet(xml, "day"),
  };
}

function parseDownloadResponse(xml) {
  return {
    fileId:       xmlGet(xml, "FILE_ID"),
    downloadUrl:  xmlGet(xml, "DOWNLOAD_URL"),
    slaves:       xmlGetAll(xml, "SLAVE"),
    encSlaves:    xmlGetAll(xml, "ENCRYPT_SLAVE"),
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

      if (res.status === 200 || res.status === 206) {
        if (!quiet) console.log("OK");
        const info = parseCheckResponse(res.body);
        info._server = server;
        info._raw = res.body;
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
 * Build full download URL list from download response
 */
function buildFullUrls(dlInfo) {
  if (!dlInfo || !dlInfo.downloadUrl) return [];
  const urls = [];
  const servers = dlInfo.slaves.length > 0
    ? dlInfo.slaves
    : dlInfo.encSlaves.length > 0
      ? dlInfo.encSlaves
      : [];

  if (servers.length > 0) {
    for (const s of servers) {
      urls.push(`https://${s}${dlInfo.downloadUrl}`);
    }
  } else {
    urls.push(dlInfo.downloadUrl);
  }
  return urls;
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

  const urls = buildFullUrls(dlInfo);
  console.log("");
  console.log("  Download URLs:");
  for (const url of urls) {
    console.log(`    ${url}`);
  }

  // Pick US-East first, fallback to first available
  const preferred = urls.find((u) => u.includes("us-east")) || urls[0];
  const outDir = opts.out || process.cwd();
  const filename = info.filename || `firmware_${curef}_${info.tv}.zip`;
  const dest = path.join(outDir, filename);

  console.log(`\n  Downloading to: ${dest}`);
  console.log(`  Size: ${formatBytes(parseInt(info.filesize || "0"))}`);
  console.log("");

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
      await runCheck(args.curef, args.fv, { mode: parseInt(args.mode) || 2 });
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
        await runCheck(args.curef, args.fv, { mode: parseInt(args.mode) || 2 });
      } else {
        printUsage();
      }
      break;
  }
}

main().catch((err) => {
  console.error(`\n  Fatal error: ${err.message}\n`);
  process.exit(1);
});
