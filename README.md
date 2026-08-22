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

## Install

```bash
pip install tcl-fw          # CLI only
pip install "tcl-fw[gui]"   # CLI + desktop app (PySide6)
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
| `tcl-fw list [curef]` | Resolve a device and list every partition: name, real size, and whether it comes from the body or the encrypted header. |
| `tcl-fw decrypt <blob>` | Decrypt a single local encrypted-header blob and name it by content. |
| `tcl-fw devices [--detect]` | List known devices, or probe for a connected phone. |
| `tcl-fw templates [--all]` | List validated firmware templates with a **NEW** tag on recent builds (`--all` shows full release history). |
| `tcl-fw sync` | Pull newly-recorded devices from the community server into your device list. |
| `tcl-fw sharing [--on\|--off]` | Show or change community device-ID sharing (opt-out, nothing personal). |

## Community device database (opt-out)

`tcl-fw` can only auto-fill a device it knows about, so it grows its own list.
When a lookup succeeds, the tool reports the device identifiers it used to a
small community registry; other installs pull those in, so a device one person
discovers becomes auto-detectable for everyone.

- **Shared:** curef, firmware version (fv), mode, resolved tv/fw_id, package
  size, TCL software version (SVN), and the tool version.
- **Never shared:** no IMEI (the FOTA protocol uses a fixed placeholder), no IP,
  no account — nothing that identifies you or your specific handset.
- **Opt-out, disclosed on first run.** Turn it off any time:

  ```bash
  tcl-fw sharing --off      # stop sharing;  --on to resume
  tcl-fw sharing            # status + exactly what's recorded
  ```

  The desktop app shows the same notice once and a checkbox at the bottom of the
  window. Submissions are fire-and-forget: if the server is unreachable the tool
  proceeds normally and simply skips the record.

The device list refreshes automatically (once a day, in the background, gated on
the same opt-out); `tcl-fw sync` pulls it on demand. The registry is public —
browse what's recorded at the server's `/about` and `/api/curefs`.

The server also **re-validates itself**: every ~12h it re-checks each known
device against TCL and records the current build, so **new firmware releases
grow the history on their own** — even for a device nobody's looked up lately.
Server code, the self-updating logic, and privacy details live in
[`curef-server/`](curef-server/).

## How it works

TCL's FOTA server delivers each partition in one of two ways, and `tcl-fw`
handles both automatically:

- **Large partitions** (`super`, `system`, `vendor`, `boot`, `md1img`, …) — the
  plaintext **body** *is* the image; it's streamed straight to disk (with resume
  and SHA-1 verification against the server's `checksum.php`).
- **Small partitions** (`lk`, `preloader`, `tee`/`atf`, `vbmeta`, `spmfw`,
  `scatter`, …) — the body is empty; the real image lives inside an encrypted
  ~4 MiB header fetched from `encrypt_header.php`. That blob is **AES-128-ECB**
  with the single universal key

  ```
  KEY = ascii( md5("TeleExtTest" + "t0523" + "jP7GHdmuBz").hexdigest()[:16] )
      = e26baba108b08a28
  ```

  The header is padded with a constant filler block, which `tcl-fw` detects and
  trims to recover the exact image.

Partitions are named **authoritatively**, never guessed. In order of preference
`tcl-fw` uses:

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
   AVB / boot / dtbo magic, and zip-wrapped payloads by their first entry.

## Output

```
pkg_<curef>/
  lk.img  boot.img  vbmeta.img  vendor.img  cache.img  userdata.img  …
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
