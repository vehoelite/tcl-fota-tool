#!/usr/bin/env python3
# =====================================================================================================
# tcl.py  --  all-in-one TCL (MediaTek) FOTA firmware puller + .mbn header decryptor.
# -----------------------------------------------------------------------------------------------------
#   * Signs & queries TCL's own FOTA download server (no Google, no account) and lists the full
#     "service"/factory package fileset: download LINKS + partition names + sizes.
#   * SMALL partitions (lk / preloader / atf / gz / tinysys / vbmeta / spmfw ...) ship with an EMPTY
#     body -- the real image is inside a 4 MiB AES-128-ECB "encrypted header". This decrypts it with
#     the built-in UNIVERSAL key -> clean, flashable images. (key cracked offline, see notes below.)
#   * LARGE partitions (super / system / boot / md1img / vendor / product ...) -- the plaintext body
#     IS the image, so it just streams the body down.
#   Result: a complete, flashable service package, pulled & decrypted fully offline. No tool / phone /
#   dongle / Windows. Stdlib + pycryptodome only.
#
# THE KEY (universal, every TCL MTK model):
#   16 AES bytes = ASCII of  MD5("TeleExtTest" + "t0523" + "jP7GHdmuBz").hexdigest()[:16]
#                = b"e26baba108b08a28"  (hex 65323662616261313038623038613238)
#   m1/m2 = the encrypt_header.php account/password; "jP7GHdmuBz" = seed in sugar_otu_r.dll.
#   verified: decrypts the header pad-block to all-zero, vbmeta->"AVB0", lk/atf/...->MTK GFH "88 16 88 58".
#
# USAGE:
#   python3 tcl.py T704SP-EAUHUS12-V                       # LIST: links + partition names + sizes
#   python3 tcl.py T704SP-EAUHUS12-V --small               # pull ONLY small parts (clean lk/preloader/... ~30MB)
#   python3 tcl.py T704SP-EAUHUS12-V --pull                # pull the COMPLETE service package (several GB!)
#   python3 tcl.py T704SP-EAUHUS12-V --pull lk,preloader,md1img   # pull only these partitions (any size)
#   python3 tcl.py <curef> --tv <TV> --fw_id <ID> --pull   # a model not in the built-in table
#   python3 tcl.py --header-file some_header.bin           # just decrypt a local 4 MiB header blob
#
#   curef on a handset:  adb shell getprop ro.tct.curef
#   pip3 install pycryptodome
# =====================================================================================================
import sys, os, time, random, hashlib, argparse
import urllib.request, urllib.parse, ssl, http.client
import xml.etree.ElementTree as ET
from collections import OrderedDict

try:
    from Crypto.Cipher import AES
except Exception:
    sys.exit("need pycryptodome:  pip3 install pycryptodome")

CTX = ssl._create_unverified_context()
UA  = "com.tcl.fota.system/7.2321.07.14078.141.0 , Android"
SRV = "master.tctsdc.com"
# download_request.php signing secret (the OLD decimal VDKEY) -- proven live
OLD = ("1271941121281905392291845155542171963889169361242115412511417616616958244916823523421516924614"
       "3771311619514022614511610020510420117572167139126116825320315911818610818366126430165962312128"
       "72211620511861302106446924625728571011411121471811641125920123641181975581511602312222261817375"
       "462445966911723844130106116313122624220514")
ENC_ACCT, ENC_PW = "TeleExtTest", "t0523"          # encrypt_header.php creds
# ---- the universal .mbn header AES-128-ECB key (cracked offline) -------------------------------------
KEY = hashlib.md5((ENC_ACCT + ENC_PW + "jP7GHdmuBz").encode()).hexdigest()[:16].encode()  # b"e26baba108b08a28"

# built-in target-version / firmware-id per curef (live-confirmed). Pass --tv/--fw_id for others.
KNOWN = {
    "T704SP-EAUHUS12-V": ("6CEVPPV0", "969459", "Verizon / Ruby_VZW / 50 XL NXTPAPER"),
    "T513Z-2ARXUS12-V":  ("9GCAZDA0", "975861", "Dish / Beryl_Dish"),
    "T702W-2ATBUS12":    ("6AASWTS0", "964377", "T-Mobile / Goldfinch_TMO"),
    "T702Z-EARXUS12-V":  ("ARATZDT0", "965341", "Dish-Boost / Goldfinch"),
    "T704SP-2AUHUS12-V": ("6CEVPPV0", "969453", "Verizon (2A variant)"),
    "T513Z-EARXUS12-V":  ("9GCAZDA0", "975713", "Dish (EA variant)"),
}

def salt(): return "%d%06d" % (int(time.time() * 1000), random.randint(0, 999999))

def vk(p, secret):
    it = list(p.items())
    q = "".join(("%s=%s%s" % (k, v, secret)) if i == len(it)-1 else ("%s=%s&" % (k, v))
                for i, (k, v) in enumerate(it))
    return hashlib.sha1(q.encode()).hexdigest()

def do_request(curef, tv, fw_id, fv="AAA000", mode=4):
    pre = OrderedDict(id="543212345000000", salt=salt(), curef=curef, fv=fv, tv=tv,
                      type="Firmware", fw_id=fw_id, mode=str(mode), cltp="10")
    p = OrderedDict(pre); p["vk"] = vk(pre, OLD)
    p["cktp"] = "2"; p["rtd"] = "1"; p["foot"] = "1"; p["chnl"] = "2"
    req = urllib.request.Request("https://%s/download_request.php" % SRV,
          data=urllib.parse.urlencode(p).encode(), headers={"User-Agent": UA})
    return ET.fromstring(urllib.request.urlopen(req, timeout=30, context=CTX).read().decode("utf-8", "replace"))

def body_size(slave, rel):
    """Range-probe the body; 0 == empty -> real image is in the encrypted header."""
    try:
        req = urllib.request.Request("http://%s%s" % (slave, rel),
              headers={"User-Agent": UA, "Range": "bytes=0-1"})
        with urllib.request.urlopen(req, timeout=25) as r:
            cr = r.headers.get("Content-Range", "")
            return int(cr.split("/")[-1]) if "/" in cr else len(r.read())
    except Exception as e:
        if getattr(e, "code", None) == 416: return 0     # 416 = empty body -> content is in the header
        return -1

def body_head(slave, rel, n=64):
    try:
        req = urllib.request.Request("http://%s%s" % (slave, rel),
              headers={"User-Agent": UA, "Range": "bytes=0-%d" % (n-1)})
        with urllib.request.urlopen(req, timeout=25) as r: return r.read(n)
    except Exception:
        return b""

def download_body(slave, rel, out):
    """Stream the plaintext body to disk (handles multi-GB partitions). Returns bytes, or -1 on error."""
    try:
        req = urllib.request.Request("http://%s%s" % (slave, rel), headers={"User-Agent": UA})
        r = urllib.request.urlopen(req, timeout=120)
    except Exception as e:
        print("  [!] download error: %s" % (getattr(e, "code", e))); return -1
    with r, open(out, "wb") as f:
        total = int(r.headers.get("Content-Length", 0)); got = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk: break
            f.write(chunk); got += len(chunk)
            if total:
                sys.stdout.write("\r      %6.1f / %6.1f MB (%3d%%)" %
                                 (got/2**20, total/2**20, 100*got//total)); sys.stdout.flush()
        sys.stdout.write("\r" + " " * 40 + "\r")
    return got

def fetch_header(encslave, rel):
    body = urllib.parse.urlencode({"account": ENC_ACCT, "password": ENC_PW, "address": rel}).encode()
    c = http.client.HTTPConnection(encslave, timeout=120)
    c.request("POST", "/encrypt_header.php", body,
              {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA,
               "Content-Length": str(len(body))})
    r = c.getresponse(); data = r.read(); c.close()
    return data

def decrypt_header(enc):
    """AES-128-ECB the 4 MiB header, then trim the trailing pad (dominant plaintext block)."""
    import collections
    n = len(enc) - (len(enc) % 16)
    dec = AES.new(KEY, AES.MODE_ECB).decrypt(enc[:n])
    domct = collections.Counter(enc[i:i+16] for i in range(0, n, 16)).most_common(1)[0][0]
    pad = AES.new(KEY, AES.MODE_ECB).decrypt(domct)
    end = len(dec)
    while end >= 16 and dec[end-16:end] == pad:
        end -= 16
    return dec[:end]

def magic_name(b):
    """Name a partition from the first bytes of its image (works for header-decrypted or body)."""
    if b[:4] == b"\x88\x16\x88\x58": return b[8:24].split(b"\x00")[0].decode("latin1", "replace") or "gfh", "img"
    if b[:4] == b"AVB0":             return "vbmeta", "img"
    if b[:4] == b"ANDR" or b[:8] == b"ANDROID!": return "boot_or_vendorboot", "img"
    if b[:4] == b"\x3a\xff\x26\xed": return "sparse", "img"       # Android sparse (super/system/...)
    if b[:4] == b"\x4d\x4d\x4d\x01": return "mtk_mmm", "img"
    if b[:5] == b"<?xml":            return "scatter_or_cfg", "xml"
    if b[:2] == b"MZ":               return "pe", "bin"
    if b[:8] == b"\x00"*8:           return "zero", "img"
    return "part_%s" % b[:4].hex(), "bin"

# ---- scatter-aware naming: identify each blob by its OWN content, then drop it into the scatter slot ----
import struct as _struct, glob as _glob, re as _re, shutil as _shutil
_ALIAS = {"md1rom":"md1img","dpmpm":"dpm","tinysys-scp":"scp","tinysys-sspm":"sspm",
          "tinysys-vcp":"vcp","tinysys-mcupm":"mcupm","atf":"tee","superheader":"super"}
def _alias(n):
    n = (n or "").lower()
    for k, v in _ALIAS.items():
        if n.startswith(k) or k in n: return v
    return n
def _ext4_label(d):
    """volume label from a sparse ext4 image (self-identifies system/vendor/product/oem/...)."""
    if d[:4] != b"\x3a\xff\x26\xed": return None
    try:
        magic,vmaj,vmin,fhdr,chdr,blk,tb,tc,crc = _struct.unpack_from("<IHHHHIIII", d, 0)
        pos, out = fhdr, b""
        for _ in range(tc):
            if pos+12 > len(d): break
            ct,_r,csz,tsz = _struct.unpack_from("<HHII", d, pos); pos += 12
            if   ct == 0xCAC1: out += d[pos:pos+csz*blk]; pos += csz*blk
            elif ct == 0xCAC2: pos += 4
            if len(out) >= 0x500: break
        if len(out) >= 0x490 and out[0x438:0x43a] == b"\x53\xef":
            lab = out[0x478:0x488].split(b"\x00")[0].decode("latin1","replace")
            return lab.rsplit("/",1)[-1] or lab       # "/mnt/vendor/otap" -> "otap"
    except Exception: pass
    return None
def _identify(path):
    """return (name, size, family, confidence) from the image's OWN content -- no XML."""
    d = open(path, "rb").read(1 << 20); sz = os.path.getsize(path)
    if d[:4] == b"\x88\x16\x88\x58": return _alias(d[8:24].split(b"\x00")[0].decode("latin1")), sz, "gfh", 1.0
    if d[:8] == b"ANDROID!":         return "boot", sz, "android", 0.5          # boot | init_boot (by size)
    if d[:4] == b"VNDR":             return "vendor_boot", sz, "vndr", 1.0
    if d[:4] == b"AVB0":             return "vbmeta", sz, "avb", 0.5            # vbmeta{,_system,_vendor}
    if d[:4] == b"\xd7\xb7\xab\x1e": return "dtbo", sz, "dtbo", 1.0
    if d[:4] == b"\x3a\xff\x26\xed":
        lab = _ext4_label(d);  return (_alias(lab) if lab else "sparse"), sz, "ext4", (0.9 if lab else 0.3)
    if d[:5] == b"<?xml":            return "scatter", sz, "xml", 1.0
    if d[:8] == b"\x00"*8:           return "zero", sz, "zero", 0.1
    return "part_"+d[:4].hex(), sz, "unknown", 0.1
def _scatter_parts(dirp):
    for x in sorted(_glob.glob(os.path.join(dirp,"*.xml")), key=os.path.getsize, reverse=True):
        raw = open(x, "rb").read()
        if b"MTK_PLATFORM_CFG" not in raw: continue
        txt = raw[raw.find(b"<?xml"):raw.rfind(b"</root>")+7].decode("latin1")
        st = [s for s in ET.fromstring(txt).findall(".//storage_type") if s.get("name")=="EMMC"][0]
        return [(p.findtext("partition_name"), p.findtext("file_name"), int(p.findtext("partition_size"),16))
                for p in st.findall("partition_index") if p.findtext("is_download")=="true"], x
    return [], None
def finalize_names(outdir):
    """Rename the pulled blobs to their scatter file_names (content-ID + size disambiguation)."""
    parts, scat = _scatter_parts(outdir)
    if not parts:
        print("[!] no scatter (*.xml MTK_PLATFORM_CFG) in %s -- skipping name step" % outdir); return
    blobs = [f for f in _glob.glob(os.path.join(outdir,"*")) if os.path.isfile(f) and not f.endswith(".xml")]
    ids = {}                                            # partition_name -> chosen blob
    used = set()
    # base partition name (strip _a slot) -> (partition_name, file_name, size)
    slots = [(pn, pn.split("_a")[0] if pn.endswith("_a") else pn, fn, psz) for pn,fn,psz in parts]
    infos = {f: _identify(f) for f in blobs}
    def take(pred):                                     # assign first unused blob matching pred
        for f in blobs:
            if f in used: continue
            if pred(f, infos[f]): used.add(f); return f
        return None
    flash = os.path.join(outdir, "flashable"); os.makedirs(flash, exist_ok=True)
    print("\n[name] scatter=%s  (%d download partitions)" % (os.path.basename(scat), len(slots)))
    mapping = []
    # 1) exact self-identified matches (GFH name / ext4 label / vndr / dtbo)
    for pn, base, fn, psz in slots:
        want = fn.rsplit(".",1)[0]
        f = take(lambda f,i: i[3] >= 0.9 and (i[0]==base or i[0]==want))
        if f: mapping.append((pn, fn, f, infos[f], "content"))
    # 2) family groups disambiguated by size: android(boot/init_boot), avb(vbmeta*), leftover sparse
    def by_family_size(fam, cand_slots):
        cand = sorted([(pn,base,fn,psz) for pn,base,fn,psz in cand_slots], key=lambda s:-s[3])
        fs = sorted([f for f in blobs if f not in used and infos[f][2]==fam], key=lambda f:-infos[f][1])
        for (pn,base,fn,psz), f in zip(cand, fs):
            used.add(f); mapping.append((pn, fn, f, infos[f], "size"))
    by_family_size("android", [s for s in slots if s[1] in ("boot","init_boot")])
    by_family_size("avb",     [s for s in slots if s[1].startswith("vbmeta")])
    by_family_size("ext4",    [s for s in slots if s[0] not in [m[0] for m in mapping]])
    # 3) whatever's left -> remaining slots by closest size
    done = {m[0] for m in mapping}
    for pn, base, fn, psz in slots:
        if pn in done: continue
        f = take(lambda f,i: True)
        if f: mapping.append((pn, fn, f, infos[f], "leftover"))
    # write flashable/ + report
    print("  %-22s %-20s %-26s %-8s %s" % ("PARTITION","FILE_NAME","(from blob)","how","sig"))
    for pn, fn, f, (nm,sz,fam,cf), how in sorted(mapping, key=lambda m:m[1]):
        _shutil.copy(f, os.path.join(flash, fn))
        print("  %-22s %-20s %-26s %-8s %s" % (pn, fn, os.path.basename(f), how, "%s/%.2f"%(fam,cf)))
    unassigned = [f for f in blobs if f not in used]
    if unassigned: print("  [unmatched blobs]:", [os.path.basename(x) for x in unassigned])
    # copy the scatter too, as the flash-tool name
    _shutil.copy(scat, os.path.join(flash, "MT6835_Android_scatter.xml"))
    print("[name] -> %s/  (flash-ready named images + MT6835_Android_scatter.xml)" % flash)

# check_new.php signing secret (NEW binary passphrase) -- used only to auto-discover tv/fw_id
NEW = "010010000110111101110111001000000110000101110010011001010010000001111001011011110111010100100000011001110110010101110100001000000111010001101000011010010111001100100000011010110110010101111001001000000111011101101111011100100110010000111111"
def check(curef, fv="000000", mode=4):
    """Auto-discover TV + FW_ID for ANY curef via check_new.php (fv=000000 = universal 'very old')."""
    pre = OrderedDict(id="543212345000000", salt=salt(), curef=curef, fv=fv, type="Firmware", mode=str(mode), cltp="10")
    p = OrderedDict(pre); p["vk"] = vk(pre, NEW)
    p["cktp"]="2"; p["rtd"]="1"; p["chnl"]="2"; p["osvs"]="15"; p["ckot"]="2"
    try:
        req = urllib.request.Request("https://%s/check_new.php" % SRV,
              data=urllib.parse.urlencode(p).encode(), headers={"User-Agent": UA})
        root = ET.fromstring(urllib.request.urlopen(req, timeout=25, context=CTX).read().decode("utf-8","replace"))
        return root.findtext(".//TV"), root.findtext(".//FW_ID")
    except Exception:
        return None, None

CH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def _check_ver(curef, fv, mode):
    pre = OrderedDict(id="543212345000000", salt=salt(), curef=curef, fv=fv, type="Firmware", mode=str(mode), cltp="10")
    p = OrderedDict(pre); p["vk"] = vk(pre, NEW)
    p["cktp"]="2"; p["rtd"]="1"; p["chnl"]="2"; p["osvs"]="15"; p["ckot"]="2"
    try:
        req = urllib.request.Request("https://%s/check_new.php" % SRV,
              data=urllib.parse.urlencode(p).encode(), headers={"User-Agent": UA})
        r = urllib.request.urlopen(req, timeout=12, context=CTX)
        if r.status != 200: return None
        root = ET.fromstring(r.read().decode("utf-8","replace"))
        tv = root.findtext(".//TV")
        return (fv, tv, root.findtext(".//FW_ID"), root.findtext(".//FILESET_COUNT")) if tv else None
    except Exception:
        return None
def list_versions(curef, latest_tv, prefixes=None):
    """Heuristic sweep of the OTA (mode=2) version space -> distinct (fv -> tv, fw_id) deltas.
       Server keeps only the latest FULL + sparse OTA deltas, so this shows what history is reachable."""
    import concurrent.futures as cf
    carrier = latest_tv[4:6] if latest_tv and len(latest_tv) >= 8 else ""
    if not prefixes:
        g = latest_tv[0] if latest_tv else "6"; prev = chr(ord(g)-1)
        prefixes = [latest_tv[:3]] + [prev+x for x in ("EE","EF","EG","EH","FA","FB","GA")]
    prefixes = list(dict.fromkeys(prefixes))
    fvs = ["%s%s%s%s0" % (P, M, carrier, M) for P in prefixes for M in CH]
    print("  latest FULL : tv=%s  fw_id=?  (type=4, the only full on the server)" % latest_tv)
    print("  sweeping %d OTA points  (prefixes=%s  carrier=%s) ..." % (len(fvs), ",".join(prefixes), carrier))
    found = {}
    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        for r in ex.map(lambda fv: _check_ver(curef, fv, 2), fvs):
            if r: found[(r[1], r[2])] = r
    if found:
        print("  OTA deltas (type=2, differential update.zip -- NOT clean full images):")
        for (tv, fw), (fv, tv2, fw2, cnt) in sorted(found.items()):
            print("    from %-11s -> tv=%-11s fw_id=%-9s files=%s" % (fv, tv, fw, cnt))
        print("  pull one:  python3 tcl.py %s --tv <TV> --fw_id <FW_ID> --ota" % curef)
    else:
        print("  no OTA deltas found in this range (try --prefixes 5EE,5EF,...).")
    return found

def _http_body(slave, rel):
    try:
        req = urllib.request.Request("http://%s%s" % (slave, rel), headers={"User-Agent": UA})
        return urllib.request.urlopen(req, timeout=60).read()
    except Exception:
        return b""
def _manifest(curef, tv):
    """check_new.php -> {FILE_ID: coded_filename}, and the .sca's FILE_ID. fv=000000 = universal 'very old'."""
    fv = "000000"
    pre = OrderedDict(id="543212345000000", salt=salt(), curef=curef, fv=fv, type="Firmware", mode="4", cltp="10")
    p = OrderedDict(pre); p["vk"] = vk(pre, NEW)
    p["cktp"]="2"; p["rtd"]="1"; p["chnl"]="2"; p["osvs"]="15"; p["ckot"]="2"
    try:
        req = urllib.request.Request("https://%s/check_new.php" % SRV,
              data=urllib.parse.urlencode(p).encode(), headers={"User-Agent": UA})
        root = ET.fromstring(urllib.request.urlopen(req, timeout=25, context=CTX).read().decode("utf-8","replace"))
    except Exception:
        return {}, None
    m, sca = {}, None
    for f in root.iter("FILE"):
        fid, nm = f.findtext("FILE_ID"), f.findtext("FILENAME")
        if fid: m[fid] = nm or ""
        if nm and nm.endswith(".sca"): sca = fid
    return m, sca
def _parse_sca(text):
    """.sca GOTU scatter -> {rename_prefix: file_name} (is_download partitions)."""
    out = {}
    for b in _re.split(r"partition_index:", text)[1:]:
        g = lambda k: (_re.search(r"\b%s:\s*([^\n\r]*)" % k, b) or [None,""])[1].strip()
        if g("is_download") == "true" and g("rename_prefix"):
            out.setdefault(g("rename_prefix"), g("file_name"))
    return out
def authoritative_names(curef, tv, byid, slave, encslave):
    """TOOL-EXACT FILE_ID -> real file_name: check_new manifest (coded names) + .sca rename_prefix map.
       join:  rename_prefix == coded[0] + coded[-2]  (2-char) or coded[0] (1-char big parts)."""
    manifest, sca_fid = _manifest(curef, tv)
    if not manifest or not sca_fid or sca_fid not in byid: return {}
    rel = byid[sca_fid]
    data = _http_body(slave, rel)
    if not data:
        enc = fetch_header(encslave, rel); data = decrypt_header(enc) if len(enc) >= 16 else b""
    sca = _parse_sca(data.decode("latin1","replace"))
    if not sca: return {}
    names = {}
    for fid, coded in manifest.items():
        if fid not in byid or not coded: continue
        base = coded.rsplit(".",1)[0]
        if coded.endswith((".sca",".txt",".xml")):
            names[fid] = coded                          # keep the scatter / info files as-is
        elif len(base) >= 2:
            names[fid] = sca.get(base[0]+base[-2]) or sca.get(base[0]) or coded
        else:
            names[fid] = sca.get(base) or coded
    return names

def resolve(curef, tv, fw_id):
    if not tv or not fw_id:
        if curef in KNOWN:
            tv = tv or KNOWN[curef][0]; fw_id = fw_id or KNOWN[curef][1]
        else:                                          # auto-discover; also try the -V variant
            print("[*] curef not built-in -- auto-discovering tv/fw_id (check_new.php)...")
            for cand in ([curef] if curef.endswith("-V") else [curef, curef+"-V"]):
                ctv, cfw = check(cand)
                if ctv and cfw:
                    curef, tv, fw_id = cand, tv or ctv, fw_id or cfw
                    print("    found: curef=%s  tv=%s  fw_id=%s" % (curef, tv, fw_id)); break
    if not tv or not fw_id:
        sys.exit("[!] could not resolve tv/fw_id for '%s'. Use the exact curef (adb shell getprop ro.tct.curef) "
                 "or pass --tv/--fw_id." % curef)
    root = do_request(curef, tv, fw_id)
    sl = root.find("SLAVE_LIST")
    slave = sl.findtext("SLAVE"); encslave = sl.findtext("ENCRYPT_SLAVE")
    files = [(f.findtext("FILE_ID"), f.findtext("DOWNLOAD_URL"), int(f.findtext("SIZE") or 0))
             for f in root.find("FILE_LIST").findall("FILE")]
    return tv, fw_id, slave, encslave, files

def get_image(slave, encslave, fid, rel):
    """Return (name, ext, bytes) for a file: decrypt header if body empty, else download body."""
    bs = body_size(slave, rel)
    if bs == 0:                                   # small partition -> image is in the encrypted header
        enc = fetch_header(encslave, rel)
        if len(enc) < 64: return None, None, None
        img = decrypt_header(enc)
        nm, ext = magic_name(img)
        return nm, ext, img                       # returned in-memory (small)
    return None, None, ("BODY", bs)               # large partition -> caller streams the body

def main():
    print("  TCL FOTA puller + .mbn decryptor · by Littlenine Ennea")
    ap = argparse.ArgumentParser(description="TCL FOTA puller + .mbn header decryptor (all-in-one).")
    ap.add_argument("curef", nargs="?")
    ap.add_argument("--tv"); ap.add_argument("--fw_id"); ap.add_argument("--fv", default="AAA000")
    ap.add_argument("--small", action="store_true", help="pull only the small header-encrypted parts (lk/preloader/... fast)")
    ap.add_argument("--pull", nargs="?", const="*", metavar="p1,p2",
                    help="pull the COMPLETE package, or a comma-list of partition-name substrings")
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--header-file", help="just decrypt a local 4MiB header blob and exit")
    ap.add_argument("--name", metavar="DIR", help="rename a pulled folder's blobs to scatter file_names -> DIR/flashable/")
    ap.add_argument("--list-versions", action="store_true", help="discover the reachable OTA version chain (history) for a curef")
    ap.add_argument("--prefixes", help="comma list of version prefixes to sweep for --list-versions (e.g. 5EE,5EF)")
    ap.add_argument("--ota", action="store_true", help="download a specific OTA fileset (mode=2 differential update.zip); needs --tv/--fw_id")
    a = ap.parse_args()

    if a.name:
        finalize_names(a.name); return

    if a.header_file:
        img = decrypt_header(open(a.header_file, "rb").read())
        nm, ext = magic_name(img); out = a.header_file + ".dec"
        open(out, "wb").write(img)
        print("    %s -> %s  (%d bytes, name=%s, starts %s)" % (a.header_file, out, len(img), nm, img[:8].hex()))
        return
    if not a.curef: ap.error("give a curef (e.g. T704SP-EAUHUS12-V), or --header-file")

    if a.list_versions:
        tv = a.tv or (KNOWN[a.curef][0] if a.curef in KNOWN else (check(a.curef)[0] or ""))
        if not tv: sys.exit("[!] could not resolve latest tv for %s" % a.curef)
        list_versions(a.curef, tv, a.prefixes.split(",") if a.prefixes else None); return
    if a.ota:
        if not (a.tv and a.fw_id): ap.error("--ota needs --tv and --fw_id (get them from --list-versions)")
        root = do_request(a.curef, a.tv, a.fw_id, mode=2)
        slave = root.find(".//SLAVE").text; encslave = root.find(".//ENCRYPT_SLAVE").text
        outdir = a.outdir or ("ota_%s_%s" % (a.curef.replace("/","_"), a.tv))
        os.makedirs(outdir, exist_ok=True); n = 0
        for f in root.find("FILE_LIST").findall("FILE"):
            fid, rel = f.findtext("FILE_ID"), f.findtext("DOWNLOAD_URL")
            out = os.path.join(outdir, "%s_%s.zip" % (a.tv, fid)); bs = body_size(slave, rel)
            if bs and bs > 16:
                print("  OTA  %s <- %s  (%.1f MB) ..." % (os.path.basename(out), fid, bs/2**20))
                if download_body(slave, rel, out) > 0: n += 1
            else:
                enc = fetch_header(encslave, rel); dec = decrypt_header(enc) if len(enc) >= 32 else b""
                if len(dec) > 64:
                    open(out, "wb").write(dec); print("  OTA  %s <- %s (enc-header, %d B)" % (os.path.basename(out), fid, len(dec))); n += 1
                else:
                    print("  [!] FILE_ID %s: OTA payload gone from CDN (404/empty) -- old OTA payloads are purged, only metadata remains." % fid)
        print("\n[%s] %d OTA file(s) -> %s/%s" % ("✓" if n else "!", n, outdir,
              "  (signed A/B update.zip; unzip -> payload_dumper payload.bin)" if n else
              "  -- nothing retrievable (this OTA's payload is purged; --list-versions still shows its metadata)"))
        return

    tv, fw_id, slave, encslave, files = resolve(a.curef, a.tv, a.fw_id)
    note = KNOWN.get(a.curef, ("", "", ""))[2]
    outdir = a.outdir or ("pkg_" + a.curef.replace("/", "_"))
    files.sort(key=lambda f: -f[2])
    print("=" * 92)
    print("TCL service package  --  %s  %s" % (a.curef, note))
    print("  tv=%s  fw_id=%s   %d files   body host=%s   header host=%s" % (tv, fw_id, len(files), slave, encslave))
    print("=" * 92)

    byid = {fid: rel for fid, rel, sz in files}
    authnames = authoritative_names(a.curef, tv, byid, slave, encslave)   # FILE_ID -> real file_name
    print("  naming : %s" % ("authoritative (check_new manifest + .sca), %d mapped" % len(authnames)
                             if authnames else "content-ID fallback (check/.sca unavailable)"))
    print("=" * 92)

    want = [w.strip().lower() for w in a.pull.split(",")] if (a.pull and a.pull != "*") else None
    do_pull = bool(a.pull) or a.small

    if not do_pull:   # LIST mode: real file_name + links
        print("  %-26s %-10s %15s  DOWNLOAD_URL (body)" % ("FILE_NAME", "FILE_ID", "SIZE"))
        for fid, rel, sz in files:
            nm = authnames.get(fid) or ("[in enc header]" if body_size(slave, rel) == 0
                                        else magic_name(body_head(slave, rel))[0])
            print("  %-26s %-10s %15s  http://%s%s" % (nm, fid, "%d (%.1fMB)"%(sz,sz/2**20) if sz else "?", slave, rel))
        print("-" * 92)
        print("  next:  --small (clean lk/preloader/... fast) | --pull (complete, GB) | --pull lk,boot,super")
        return

    def realname(fid, rel, small):
        nm = authnames.get(fid)
        if nm: return nm                                    # server-authoritative name (lk.img, ...)
        if small:                                           # fallback: identify by content
            h = fetch_header(encslave, rel)
            if len(h) < 64: return None
            n, e = magic_name(decrypt_header(h)); return "%s_%s.%s" % (n, fid, e)
        n, e = magic_name(body_head(slave, rel)); return "%s_%s.%s" % (n, fid, e)

    os.makedirs(outdir, exist_ok=True); print("[*] output -> %s/\n" % outdir)
    n_ok = 0; used = set()
    for fid, rel, sz in files:
        bs = body_size(slave, rel); small = (bs <= 0)     # empty body (or 416) -> content in header
        if a.small and not small: continue
        nm = realname(fid, rel, small)
        if not nm: continue
        stem = os.path.splitext(nm)[0].lower()            # precise filter: whole stem, not substring
        if want and not any(stem == w or stem.startswith(w + "_") or stem.startswith(w + ".") or stem == w for w in want): continue
        if nm in used:                                      # e.g. preloader + preloader_backup share a name
            r_, e_ = os.path.splitext(nm); nm = "%s_%s%s" % (r_, fid, e_)
        used.add(nm); out = os.path.join(outdir, nm)
        if small:
            h = fetch_header(encslave, rel)
            if len(h) < 64: continue
            open(out, "wb").write(decrypt_header(h)); print("  DEC   %-28s <- FILE_ID %s" % (nm, fid))
        else:
            print("  BODY  %-28s <- FILE_ID %s  (%.1f MB)" % (nm, fid, bs/2**20)); download_body(slave, rel, out)
        n_ok += 1
    print("\n[✓] %d files -> %s/  (named by the tool's own manifest + .sca -- flash-ready, no guessing)" % (n_ok, outdir))

if __name__ == "__main__":
    main()
