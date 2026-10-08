# tcl-fw

**Pull and decrypt official TCL (MediaTek) firmware — flashable service packages, fully offline.**

`tcl-fw` talks to TCL's own FOTA download servers the way the on-device updater
does (no Google, no account, no dongle), lists a device's complete factory
"service" fileset, streams the plaintext partitions, and **AES-decrypts** the
small partitions that ship inside an encrypted 4 MiB header — producing clean,
flashable images (`lk.img`, `boot.img`, `vbmeta.img`, `preloader_*.bin`, the
scatter, …).

> ### Credit
> The header-decryption scheme that makes this tool possible — **AES-128-ECB
> with a universal key recovered from `sugar_otu_r.dll`** — was cracked by
> **[Littlenine Ennea](https://github.com/LittlenineEnnea)**. Mode 4 (full-image
> decryption) exists entirely because of that work. Thank you.

Works on TCL-made Android devices (TCL, REVVL, Alcatel).

---

## What's new in 4.5.0 — bugs report themselves

* **Anonymous error reports**, under the same opt-out switch as device sharing
  and published in full — see [what's sent and what never is](#anonymous-error-reports-same-switch).
  The goal: a bug like 4.x's missing footer (#15) gets noticed in days, not
  weeks, even when nobody is actively working on the tool.
* The sharing notice is shown once more to existing users so the change is
  disclosed, and the desktop app's notice now lists everything that is shared
  (it had not mentioned the device model name).

## What's new in 4.4.0 — byte-exact images

**Every large-partition image pulled with 4.x was incomplete. Re-pull with
4.4.0, and do not flash images pulled with an earlier 4.x release.**

* **Large partitions were missing their final 4 MiB** ([#15]). TCL serves each
  partition as a body plus an encrypted header blob, and for large partitions
  that blob is the image's last 4 MiB. 4.x saved the body alone. Sparse images
  (`system`, `vendor`, `product`, …) failed `simg2img`; zip containers lost their
  central directory; and `boot`, `dtbo` and `vendor_dlkm` lost their **AVB
  footer**, so they would fail verified boot. Every image is now
  `body + decrypt(header blob)`, on the zip-wrapped path too.
* **Header images kept their padding** ([#16]). The blob is standard PKCS#7, but
  the old trimmer looked for a "dominant filler block" that isn't there and
  removed nothing — so `vbmeta`, `lk`, `superheader`, … were 1–16 bytes too long.
  Padding is now stripped exactly, and invalid padding is refused.
* **Checksums were never actually checked.** `checksum.php` answers in XML; the
  parser expected JSON, failed, and quietly returned nothing. Every byte of every
  image is now verified against TCL's own SHA-1s, mismatches write nothing, and
  anything that *couldn't* be verified is reported as such.
* **Make flashable works on `.sca` devices** ([#17]). It only read the MTK
  scatter XML, so devices that ship TCL's `.sca` instead (e.g. T611B) got "No
  MTK scatter in this folder". The `.sca` *is* an MTK scatter — the text form
  SP Flash Tool loads — and is now read directly.
* **GUI: partition names load again on recent PySide6.** Load handed Qt a
  string where it wanted a bool; newer PySide6 rejects that, so Load stopped
  before naming unnamed partitions (they showed as bare FILE_IDs).
* Files TCL's CDN no longer has (expired OTA deltas) say so, instead of a
  generic "probe failed" that invited retrying forever.
* Re-running a pull no longer mistakes a short 4.x image for a complete one.
* `--only` accepts FILE_IDs (devices without a `.sca` have no names to match),
  and selecting nothing is an error instead of a green "0/0 files".

Thanks to **[@jgroman](https://github.com/jgroman)** for the precise diagnosis
of both #15 and #16.

[#15]: https://github.com/vehoelite/tcl-fota-tool/issues/15
[#16]: https://github.com/vehoelite/tcl-fota-tool/issues/16
[#17]: https://github.com/vehoelite/tcl-fota-tool/issues/17

## What's new in 4.3.1 — safety patch

A review of the naming path found three ways the tool could write the **wrong
bytes under a right-looking filename**. None of them have been reported in the
wild, and all three are fixed here. If you pull firmware with `tcl-fw`, update.

* **Two partitions could be written to one file.** The `.sca` join is not
  injective, so several coded names can resolve to one real name (`lk.img`).
  Because the authoritative path used that name verbatim, two images could
  share a destination — and a resumed download would **append** the second onto
  the first, producing a spliced image under a clean, trusted-looking name.
  Destinations are now reserved: a later claimant is suffixed with its
  `FILE_ID`, and the clash is reported and recorded in `manifest.json`.
* **A network blip could turn a partition into its own header.** A failed size
  probe returned `-1`, which the pull path read as "empty body" — the signal
  meaning *the image lives in the encrypted header*. A timeout on a large
  partition would therefore decrypt its 4 MiB header and write **that** out as
  the image. A failed probe is now distinct from an empty body: the tool
  re-probes once and then refuses to guess, reporting the file as not pulled.
* **`pack` could rename `recovery.img` to `boot.img`.** Boot-family images were
  told apart by size (larger = `boot`, smaller = `init_boot`). `init_boot` only
  exists on Android 13+ GKI devices; on the non-A/B devices common in TCL's MTK
  line the second `ANDROID!` image is `recovery`, and recovery is usually the
  larger. This ran at a confidence above the rename threshold. Boot images are
  now classified by their header fields, and a genuinely ambiguous pair is left
  alone for a human instead of guessed.

Also: downloads stage to a `FILE_ID`-keyed `.part` file, so a partial pull never
looks like a flashable image; content guesses are kept out of the dictionary
reserved for server-authoritative names; and `alias()` no longer matches on bare
substrings (a partition labelled `platform` came out named `tee`, because "atf"
is a substring of "platform").

---

## Install

```bash
pip install tcl-fw          # CLI only
pip install "tcl-fw[gui]"   # CLI + desktop app (PySide6)
pip install "tcl-fw[verify]" # + signature verification (cryptography + pyasn1)
```

Or grab the standalone `tcl-fw` / `tcl-fw.exe` (CLI) or `tcl-fw-gui.exe`
(desktop app) from
[Releases](https://github.com/vehoelite/tcl-fota-tool/releases) — no Python needed.

## Desktop app

Prefer clicking to typing? Launch the GUI:

```bash
tcl-fw-gui        # or:  python -m tcl_fw_gui
```

Pick (or **Detect**) a device → **Load** to see every partition with real sizes
→ tick what you want → **Pull**. Per-partition progress, live decrypt log, and
SHA-1 verification, all over the exact same backend as the CLI. On Windows the
GUI uses the native `adb`, so **Detect phone** works without any usbipd/WSL
plumbing.

Click **🔥 Firmware (Auto-updated)** to browse the community device database in
place of the partition list — every device/build the tool has learned about
(CUREF/MODEL, Version, Date, Size, Mode, SW ver). Double-click a row to load
that device. The list grows on its own (see below).

## Quickstart

```bash
# Plug in a phone with USB debugging on — tcl-fw reads the curef itself:
tcl-fw pull

# …or name the device explicitly:
tcl-fw list  T704SP-EAUHUS12-V          # see every partition, size, name
tcl-fw pull  T704SP-EAUHUS12-V          # download + decrypt the whole package
tcl-fw pull  T704SP-EAUHUS12-V --small  # just the small parts (lk/preloader/… fast)
tcl-fw pull  T704SP-EAUHUS12-V --only lk,boot,vbmeta
tcl-fw decrypt some_header.bin          # decrypt one local header blob
```

Find your curef on a handset:

```bash
adb shell getprop ro.tct.curef
```

## Commands

| Command | What it does |
|---|---|
| `tcl-fw pull [curef]` | Download + decrypt a device's service package into flashable images. Auto-detects the curef from a plugged-in phone if omitted. `--small`, `--only p1,p2`, `--out DIR`, `--no-verify`. |
| `tcl-fw list [curef]` | Resolve a device and list every partition: name, body size, and whether it comes from the body or the encrypted header. |
| `tcl-fw decrypt <blob>` | Decrypt a single local encrypted-header blob and name it by content. |
| `tcl-fw devices [--detect]` | List known devices, or probe for a connected phone. |
| `tcl-fw templates [--all]` | List validated firmware templates with a **NEW** tag on recent builds (`--all` shows full release history). |
| `tcl-fw sync` | Pull newly-recorded devices from the community server into your device list. |
| `tcl-fw sharing [--on\|--off]` | Show or change community device-ID sharing (opt-out, nothing personal). |
| `tcl-fw verify <file>` | Verify an APK / signed package's signature, or inspect the signing certificates inside a firmware blob. `--against <cert>` for a strict identity check. Needs `pip install "tcl-fw[verify]"`. |

## Community device database & error reports (opt-out)

`tcl-fw` can only auto-fill a device it knows about, so it grows its own list.
When a lookup succeeds, the tool reports the device identifiers it used to a
small community registry; other installs pull those in, so a device one person
discovers becomes auto-detectable for everyone.

- **Shared:** curef, firmware version (fv), mode, resolved tv/fw_id, package
  size, TCL software version (SVN), the **device model name**, and the tool
  version. The model name comes from a read-only build property
  (`ro.tct.setupwizard.marketname`, else `ro.product.model`) — it is identical
  on every unit of that model, so it names the *model*, never your phone. It is
  only sent when a matching handset is plugged in; otherwise it is simply
  omitted.
- **Never shared:** no IMEI or serial (the FOTA protocol uses a fixed
  placeholder), no IP, no account, no personal name, no location, and no
  user-set device nickname — nothing that identifies you or your specific
  handset.
- **Opt-out, disclosed on first run.** Turn it off any time:

  ```bash
  tcl-fw sharing --off      # stop sharing;  --on to resume
  tcl-fw sharing            # status + exactly what's recorded
  ```

  The desktop app shows the same notice once and a checkbox at the bottom of the
  window. Submissions are fire-and-forget: if the server is unreachable the tool
  proceeds normally and simply skips the record.

The device list refreshes automatically (once a day, in the background, gated on
the same opt-out); `tcl-fw sync` pulls it on demand. Everything it learns shows
up in **`tcl-fw devices`**, which marks each entry `built-in`, `bundled`, or
`community` so you can see what the network taught your install. The registry is
public — browse what's recorded at the server's `/about` and `/api/curefs`.

### Anonymous error reports (same switch)

`tcl-fw` is maintained in spare time — sometimes a session or two a month. So
that a serious bug can't quietly ride along for weeks between those sessions,
**the same opt-out switch also sends anonymous error reports**: when a pull
fails, a checksum doesn't match, an image can't be verified, or the tool
crashes. They are grouped by error and version and **published in full** at the
server's `/api/errors`, so anyone can see what's broken and what's being fixed.

A report contains exactly this, and nothing else:

| field | example | why |
|---|---|---|
| `code` | `body_checksum_mismatch`, `cdn_404`, `unverified`, `exception` | what went wrong — a fixed list, never free text |
| `exc_type`, `errno` | `PermissionError`, `13` | the kind of crash — the type's *name* only |
| `stack` | `tcl_fw.puller:pull_one:250` | where in tcl-fw — `module:function:line`, tcl-fw's own code only |
| `tool_version`, `python`, `pyside`, `os` | `4.5.0`, `3.12`, `6.11.2`, `Windows` | which builds are affected (OS *family* only) |
| `command` | `pull` | which feature |
| `curef`, `tv`, `fw_id`, `mode` | `T611B-2ALCGB12` | which device — the same IDs already shared above |

**Never sent:** the error *message* (messages routinely contain file paths and
your username), file paths, folder names, your username, command-line
arguments, anything you typed. This isn't scrubbing — those fields simply don't
exist in a report, the server discards anything outside the list above, and a
test (`tests/test_reporting.py`) fails the build if a path or username ever
reaches the wire. A pull sends at most one report (with counts), a clean pull
sends nothing, and a process sends at most ten.

Existing users see the updated notice once after upgrading.
`tcl-fw sharing --off` turns off both device sharing and error reports.

The server also **re-validates itself**: every ~12h it re-checks each known
device against TCL and records the current build, so **new firmware releases
grow the history on their own** — even for a device nobody's looked up lately.
Server code, the self-updating logic, and privacy details live in
[`curef-server/`](curef-server/).

## Verify signatures (`verify`)

`tcl-fw verify` answers two questions using the certificates that ship in the
firmware itself:

```bash
tcl-fw verify some.apk                  # is this genuinely signed + untampered?
tcl-fw verify some.apk --against rk.pem # …and by exactly this key?
tcl-fw verify vendor_map_*.zip          # which signing cert(s) does this blob carry?
```

For an APK / signed zip it runs the full **Android v1 (JAR)** check — the
`CERT.RSA` signature over `CERT.SF`, `CERT.SF`'s digest over the manifest, and
the manifest's digest over **every file** — so it catches both a wrong signer
and any modified byte, and reports who signed it (flagging official TCL keys).
For a firmware blob it extracts and describes the signing certificates inside
(`releasekey.x509.pem`, `otacerts.zip`, …) — the trust anchors a device checks
its updates against. It reads even the truncated zips TCL ships, which `unzip`
refuses.

> **It verifies; it cannot sign.** Verification uses a *public* certificate.
> Creating a signature a device would trust needs the matching *private* key,
> which lives in TCL's build HSM and never ships in firmware. Nothing here
> bypasses verified boot. (This is a different key entirely from the universal
> AES key the tool uses to *decrypt* download headers — see below.)

## How it works

TCL's FOTA server splits every partition into two parts, and the flashable
image is always

```
image = body  +  decrypt(header blob)
```

- The **body** is plaintext, streamed from the download CDN (with resume).
- The **header blob** comes from `encrypt_header.php`. For a **large** partition
  (`system`, `vendor`, `boot`, …) it holds the image's **final 4 MiB** — which
  carries things like the AVB footer and the end of a sparse chunk table. For a
  **small** partition (`lk`, `preloader`, `tee`, `vbmeta`, the scatter, …) the
  body is empty and the blob is the whole image.

  The blob is **AES-128-ECB** with the single universal key

  ```
  KEY = ascii( md5("TeleExtTest" + "t0523" + "jP7GHdmuBz").hexdigest()[:16] )
      = e26baba108b08a28
  ```

  over standard **PKCS#7**-padded plaintext, which `tcl-fw` strips exactly —
  and refuses, rather than guesses, if the padding isn't valid.

**Every byte is verified.** `checksum.php` publishes a SHA-1 of the body
(`BODY`) and of the decrypted, unpadded blob (`FOOTER`). `tcl-fw` checks both
for every partition, verifies the blob *before* downloading a multi-GB body, and
on any mismatch writes nothing. If the server offers no checksum the image is
still written but reported as **unverified**, never silently passed.

Partitions are named from the **best evidence available**, and the tool is
explicit about which it had. In order of preference `tcl-fw` uses:

1. **The `.sca` scatter** — the `check_new.php` manifest joined to the scatter's
   `rename_prefix → file_name` map (real names like `lk.img`, `vbmeta.img`).
2. **An embedded manifest** — some devices serve *no* top-level scatter but
   bundle one inside a `target_files` zip. `tcl-fw` reads its `misc_info.txt`,
   `scatter_emmc.txt`, and `ota_update_list.txt` to name filesystem partitions
   by size (this is the scatter-first source TCL's own OTU engine relies on) and
   drops those descriptors next to the images.
3. **Content identification** — MTK GFH partition name, the **ext4 / f2fs /
   erofs** superblock read *through* the Android sparse container (so a sparse
   `vendor`/`cache`/`userdata` comes out named, not as an anonymous `sparse`),
   AVB / boot / dtbo magic, and zip-wrapped payloads by what's inside them.

Only (1) and (2) are authoritative; (3) is inference from the bytes, and a name
that came from it always carries the `FILE_ID` suffix (`vbmeta_664532.img`) to
say so. Two files can never share a destination: if a name is already taken the
second file is suffixed and the clash is reported at the end of the pull and
recorded as `"collided": true` in `manifest.json`. **At most one of a clashing
pair is really that partition — check both before flashing either.**

Some magics are genuinely ambiguous and the tool does not pretend otherwise:
`ANDROID!` is shared by `boot` / `init_boot` / `recovery`, and `AVB0` by
`vbmeta` / `vbmeta_system` / `vbmeta_vendor`. Resolving these properly (from the
AVB footer each image carries) is the subject of the next release.

### Wrapped partitions

TCL ships the largest filesystem partitions **triple-wrapped**: a zip containing
a `.mbn`, which is an Android **sparse** image, which is the actual ext4
filesystem. Handed over as-is it's an opaque archive that even `unzip` may
refuse (the entry is bigger than 4 GiB of plain deflate, and a partial download
has no readable central directory).

`tcl-fw` **unwraps these in-flight**: the container is inflated as it downloads,
so what lands on disk is `system.img` — the real partition image — and the
720 MB archive is never written at all. The container's last 4 MiB arrive in
the header blob, and the deflate stream runs straight across that seam, so the
decrypted blob is fed through the same inflater after the body. The body bytes
are hashed *as served*, so the server's SHA-1 still verifies. A short body is rejected and the partial image
deleted rather than left looking complete.

Zips that hold ordinary files (`system.map`, `vendor.map`, the `target_files`
manifest) are **not** partitions and are deliberately left alone.

## Output

```
pkg_<curef>/
  lk.img  boot.img  vbmeta.img  system.img  vendor.img  cache.img  userdata.img  …
  <device>.sca            # the flash-tool scatter (when the server serves one)
  scatter_emmc.txt        # recovered partition layout (embedded-manifest devices)
  misc_info.txt           # partition fs types + sizes (embedded-manifest devices)
  manifest.json           # what was pulled, sizes, checksum results, manifest
```

Feed these to SP Flash Tool, `fastboot`, or `mtkclient`. Filesystem partitions
land as Android **sparse** images — flash them as-is, or expand to raw with
`simg2img` when you want to mount and inspect.

## Make it flashable (`pack`)

A service pack names every file only by a numeric ID, but it ships the device's
**MTK scatter**. `tcl-fw` reads that scatter to rename the images to their real
partition names and write a ready-to-load SP Flash Tool scatter:

```bash
tcl-fw pull T702Z-EARXUS12-V --pack     # pull, then auto-pack
tcl-fw pack pkg_T702Z-EARXUS12-V        # or pack a folder you already pulled
tcl-fw pack pkg_… --dry-run             # preview the mapping, rename nothing
```

In the GUI, click **⚡ Make flashable** after a pull. Result:

```
pkg_<curef>/
  boot.img  init_boot.img  vendor_boot.img  dtbo.img  vbmeta*.img
  system.img  vendor.img  product.img  system_ext.img  preloader_*.bin  …
  MT6835_Android_scatter.txt      # load this in SP Flash Tool / mtkclient
```

Partitions are matched by content (MTK-GFH name, AVB descriptors, dtbo/boot
magic, ext4/erofs label) and, for the big filesystem images, by size-fit against
the scatter. Anything it can't place **confidently** is left untouched and
listed for you to name by hand — it never guesses a partition into a wrong name.

## Related — Image Anarchy

Pulled a package and want to flash, repack, or explore it? Check out
**[Image Anarchy](https://github.com/vehoelite/image-anarchy)** — a companion
toolkit for working with Android firmware images. `tcl-fw` gets you the clean,
named partitions; Image Anarchy helps you do something with them.

## Legal / ethical use

This tool downloads firmware that TCL's own servers serve publicly, for the
purpose of repairing, restoring, or inspecting **a device you own**. It uses no
exploit against the device and asks the servers only for what the on-device
updater already requests. Respect your local laws and TCL's terms.

## Credits

- **[Littlenine Ennea](https://github.com/LittlenineEnnea)** — cracked the
  AES-128-ECB header-decryption scheme and the universal key; the reference
  implementation lives in [`mode4/tcl-fw.py`](mode4/tcl-fw.py). Mode 4 is theirs.
- **[vehoelite](https://github.com/vehoelite)** — the original `tcl-fota-tool`
  FOTA protocol client (check/download signing, fileset parsing), preserved in
  [`legacy/`](legacy/), and the companion
  [Image Anarchy](https://github.com/vehoelite/image-anarchy) firmware toolkit.
- Predecessor protocol research: `mbirth/tcl_ota_check`, `thurask/bbarchivist`.

## License

MIT — see [LICENSE](LICENSE).
