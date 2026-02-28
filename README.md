# tcl-fota

**Firmware update checker & downloader for TCL / REVVL / Alcatel devices.**

Query TCL's FOTA (Firmware Over The Air) servers to check for available firmware updates and get direct download URLs — for any TCL-manufactured Android device.

```
  ╔════════════════════════════════════════════════════╗
  ║           tcl-fota — TCL Firmware Tool            ║
  ║    Firmware checker & downloader for TCL/REVVL    ║
  ╚════════════════════════════════════════════════════╝
```

## Features

- **Check for updates** — See available firmware versions for any TCL device
- **Direct download URLs** — Get CDN links to download firmware directly
- **Download with progress** — Built-in downloader with progress bar
- **Interactive mode** — Guided experience, no command-line args needed
- **Known device list** — Pre-configured CUREFs for popular TCL/REVVL models
- **Zero dependencies** — Uses only Node.js built-in modules
- **Works for any TCL device** — TCL, REVVL (T-Mobile), Alcatel, and other TCL-made phones

## How It Works

TCL phones use a proprietary FOTA (Firmware Over The Air) system to check for and download updates. This tool implements the same protocol by:

1. Sending a `check_new.php` POST request with device identifiers and a verification hash (VK)
2. Parsing the XML response for update information (version, file size, checksum)
3. Sending a `download_request_new.php` POST to get time-limited CDN download URLs
4. Optionally downloading the firmware ZIP directly

The VK verification hash was reverse-engineered by decompiling the `com.tcl.fota.system` APK (v7.2321.07.14078.141.0) using [jadx](https://github.com/skylot/jadx). The key discovery was a binary-encoded string in `com/tcl/fota/common/utils/g.java` that serves as the hash suffix.

## Requirements

- **Node.js** 14 or newer (no npm install needed — zero dependencies)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/<your-username>/tcl-fota.git
cd tcl-fota

# Check for updates (replace with your device's CUREF and FV)
node tcl-fota.js check --curef T702Z-EARXUS12-V --fv 9LBHZDH0

# Download firmware
node tcl-fota.js download --curef T702Z-EARXUS12-V --fv 9LBHZDH0

# Interactive mode (guided)
node tcl-fota.js interactive

# List known devices
node tcl-fota.js list
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `check` | Check for available firmware update |
| `download` | Check + download firmware file |
| `list` | Show known device CUREFs |
| `interactive` | Guided mode (no arguments needed) |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--curef <val>` | Device CUREF identifier | *(required)* |
| `--fv <val>` | Current firmware version | *(required)* |
| `--mode <2\|4>` | 2=OTA incremental, 4=FULL image | `2` |
| `--imei <val>` | Device IMEI | dummy value |
| `--out <dir>` | Output directory for downloads | current dir |

### Examples

```bash
# Check for OTA update
node tcl-fota.js check --curef T702Z-EARXUS12-V --fv 9LBHZDH0

# Check for FULL firmware image
node tcl-fota.js check --curef T702Z-EARXUS12-V --fv 9LBHZDH0 --mode 4

# Download to specific directory
node tcl-fota.js download --curef T702Z-EARXUS12-V --fv 9LBHZDH0 --out ./firmware
```

### Sample Output

```
  Device:   T702Z-EARXUS12-V
  Current:  9LBHZDH0
  Mode:     OTA

  Checking for updates...
  Checking master.tctsdc.com... OK

  ┌─────────────── Update Available ───────────────┐
  │  CUREF:    T702Z-EARXUS12-V                    │
  │  From:     9LBHZDH0                            │
  │  To:       ARAEZDE0                            │
  │  FW ID:    927360                              │
  │  File:     JSU_T702Z-E[A]RXUS12_ARAEZDE0.zip  │
  │  Size:     4.1 GB                              │
  │  SHA-1:    b2eff48108561137d82b5df1118a063913…  │
  │  Released: 2025-12-24                          │
  └───────────────────────────────────────────────┘
```

## Finding Your Device's CUREF and FV

The two values you need are:

- **CUREF** — A unique identifier for your device model + carrier variant (e.g., `T702Z-EARXUS12-V`)
- **FV** — Your current firmware version code (e.g., `9LBHZDH0`)

### Method 1: ADB (recommended)

```bash
adb shell getprop ro.boot.hardware.curef
adb shell getprop ro.build.fota.version
```

### Method 2: Phone Settings

Go to **Settings → About Phone** and look for:
- "CUREF" or "Product reference"
- "Build number" or "Firmware version"

### Method 3: FOTA App

Some TCL phones show the CUREF in **Settings → System → System update → About**.

## Known Devices

| Device | CUREF |
|--------|-------|
| TCL T702Z (Dish/Boost) | `T702Z-EARXUS12-V` |
| TCL 30 XE 5G | `T776B-2ALGUS12-V` |
| TCL 30 V 5G | `T781S-2ALGUS12-V` |
| TCL REVVL V+ 5G | `T618DL-2ALGUS12-V` |
| TCL REVVL 6 5G | `T608DL-2ALGUS12-V` |
| TCL REVVL 6 Pro 5G | `T609DL-2ALGUS12-V` |
| TCL REVVL 7 5G | `T701DL-2ALGUS12-V` |
| TCL REVVL 7 Pro 5G | `T702DL-2ALGUS12-V` |
| Alcatel Joy Tab 2 | `9032Z-2ALGUS12-V` |

> **Note:** Some CUREFs above are approximate. If yours doesn't work, use ADB to find the exact value. PRs with confirmed CUREFs are welcome!

## Technical Details

### Protocol Overview

TCL's FOTA system uses two main API endpoints on `master.tctsdc.com`:

1. **`/check_new.php`** (POST) — Check for available updates
2. **`/download_request_new.php`** (POST) — Get time-limited download URLs

Both endpoints require a VK (verification key) parameter — a SHA-1 hash of the request parameters plus a secret suffix.

### VK Hash Computation

The VK is computed by:

1. Building a string of ordered parameters: `key1=val1&key2=val2&...&lastKey=lastVal`
2. Appending a binary-encoded suffix directly after the last value (no `&` separator)
3. Computing SHA-1 of the resulting string
4. Converting to lowercase hex

The suffix is a string of `0` and `1` characters representing the ASCII binary encoding of a passphrase. It was found by decompiling the FOTA APK and analyzing `com/tcl/fota/common/utils/g.java`.

### Parameter Ordering

Parameters must be in the exact LinkedHashMap order used by the FOTA app:

**check_new.php:** `id, salt, curef, fv, type, mode, cltp` → *compute VK* → `vk, cktp, rtd, chnl, osvs, ckot`

**download_request_new.php:** `id, salt, curef, fv, tv, type, fw_id, mode, cltp` → *compute VK* → `vk, cktp, rtd, chnl`

### Servers

| Server | Use |
|--------|-----|
| `master.tctsdc.com` | Primary (non-China) |
| `g2master-cn-south.tclclouds.com` | China mainland |
| `g2master-{region}.tclclouds.com` | Regional replicas |
| `g2slave-{region}.tclcom.com` | CDN download servers |

### Download URLs

Download URLs are time-limited tokens. If a URL expires, simply run the tool again to generate a fresh one.

## Troubleshooting

### "No update found"
- Verify your CUREF and FV are correct (use ADB method above)
- Try `--mode 4` for full firmware instead of OTA
- Your firmware may already be the latest version

### "VK parameter not expected"
- This means the VK hash algorithm has changed. Please [open an issue](https://github.com/<your-username>/tcl-fota/issues).

### Download URL expired
- Run the tool again — it generates a fresh time-limited URL each time

### Connection timeouts
- TCL's servers can be slow. The tool tries multiple servers automatically.
- Regional servers closer to you may respond faster.

## Contributing

Contributions are welcome! Especially:

- **New device CUREFs** — If you've confirmed your device's CUREF works, submit a PR
- **Bug reports** — If the VK hash or protocol changes, let us know
- **Other TCL brands** — BlackBerry (TCL-made), Palm (TCL), etc.

## Credits

- **Reverse engineering** — Protocol discovered with assistance from Claude (Anthropic, Opus 4.6), by decompiling TCL's FOTA system APK using [jadx](https://github.com/skylot/jadx)
- **Original research** — Earlier protocol work by [mbirth/tcl_ota_check](https://github.com/mbirth/tcl_ota_check) (archived) and [jcrutchvt10/tclotacheck](https://github.com/jcrutchvt10/tclotacheck) which documented the older API version
- **Community** — TCL modding community for device identification and testing

## Disclaimer

This tool is provided for informational and research purposes. Use at your own risk. Firmware files are property of TCL Communication. This tool does not bypass any encryption or DRM — it uses the same public API that your phone's built-in updater uses, just on your desktop.

## License

MIT
