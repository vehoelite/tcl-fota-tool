/**
 * fota.js — the minimum of TCL's FOTA check protocol needed to re-validate a
 * curef server-side: sign a check_new.php request with the VK secret and read
 * back the latest tv / fw_id / SVN / total size.
 *
 * Zero dependencies (Node https + crypto). Mirrors tcl_fw/fota.py's discover().
 */

"use strict";

const https = require("https");
const crypto = require("crypto");

const SERVER = "master.tctsdc.com";
const UA = "com.tcl.fota.system/7.2321.07.14078.141.0 , Android";

// check_new.php signing secret: the ASCII passphrase, byte-by-byte as 8-bit
// binary text ("How are you get this key word?").
const NEW = [...Buffer.from("How are you get this key word?")]
  .map((b) => b.toString(2).padStart(8, "0"))
  .join("");

function salt() {
  return `${Date.now()}${String(Math.floor(Math.random() * 1e6)).padStart(6, "0")}`;
}

/** VK = SHA-1 over 'k1=v1&...&kN=vN{secret}' (secret glued to the last value). */
function vk(pairs, secret) {
  let q = "";
  for (let i = 0; i < pairs.length; i++) {
    const [k, v] = pairs[i];
    q += i === pairs.length - 1 ? `${k}=${v}${secret}` : `${k}=${v}&`;
  }
  return crypto.createHash("sha1").update(q).digest("hex");
}

function post(path, params, timeout = 25000) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const req = https.request(
      {
        host: SERVER, path: "/" + path, method: "POST",
        rejectUnauthorized: false,   // TCL serves a cert Node won't chain-verify
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(body),
          "User-Agent": UA,
        },
        timeout,
      },
      (res) => {
        let d = "";
        res.on("data", (c) => (d += c));
        res.on("end", () => resolve({ status: res.statusCode, body: d }));
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.write(body);
    req.end();
  });
}

function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}>([^<]+)</${name}>`));
  return m ? m[1].trim() : null;
}

/**
 * Check a curef's latest build. mode 4 (fv=000000) asks for the current full
 * image and is fv-independent. Returns {tv, fw_id, svn, size} or null.
 */
async function check(curef, mode = 4, fv = "000000") {
  const pre = [
    ["id", "543212345000000"], ["salt", salt()], ["curef", curef],
    ["fv", fv], ["type", "Firmware"], ["mode", String(mode)], ["cltp", "10"],
  ];
  const params = Object.fromEntries(pre);
  params.vk = vk(pre, NEW);
  Object.assign(params, { cktp: "2", rtd: "1", chnl: "2", osvs: "15", ckot: "2" });

  let r;
  try {
    r = await post("check_new.php", params);
  } catch {
    return null;
  }
  if (![200, 206, 207].includes(r.status)) return null;  // 204/404 = nothing here

  const tv = tag(r.body, "TV");
  const fw_id = tag(r.body, "FW_ID");
  if (!tv || !fw_id) return null;
  let size = 0;
  for (const m of r.body.matchAll(/<SIZE>(\d+)<\/SIZE>/g)) size += parseInt(m[1], 10);
  return { tv, fw_id, svn: tag(r.body, "SVN"), size: size || null };
}

module.exports = { check };
