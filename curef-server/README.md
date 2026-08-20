# tcl-curef server

A tiny, dependency-free registry of the `(curef, fv)` device identifiers the
`tcl-fw` tool looks up. When users leave sharing on, the tool reports the device
IDs it just used, so the built-in device list and firmware templates grow by
themselves.

## What it stores

Only device identifiers — nothing personal:

| field | example | notes |
|-------|---------|-------|
| `curef` | `T807W-EATBUS12-V` | TCL product id |
| `fv` | `AXAMWTM0` | firmware version (optional — omitted for curef-only lookups) |
| `mode` | `4` | 2 = OTA, 4 = FULL |
| `tv`, `fw_id` | `AXAMWTM0`, `983299` | resolved target build |
| `size` | `9663676416` | total package size in bytes (optional) |
| `svn` | `v9.0.AXAM` | TCL software version (optional) |
| `tool_version` | `3.5.0` | which client reported it |
| `count`, `first_seen`, `last_seen` | | aggregation |

**Not** stored: IMEI (the FOTA protocol uses a fixed placeholder), IP addresses,
accounts, names, or locations. Reads are public so anyone can audit what's held.

## Endpoints

| method | path | auth | purpose |
|--------|------|------|---------|
| POST | `/api/curef` | `x-tcl-key` header | record a `{curef, fv, mode, tv, fw_id, tool_version}` |
| GET | `/api/curefs?limit=&offset=` | public | list records (newest first) |
| GET | `/api/templates` | public | validated records reshaped as per-device release history — the feed `tcl-fw sync` merges to auto-grow its device list |
| GET | `/api/stats` | public | `{devices, combos, total, updated}` |
| GET | `/about` (or `/`) | public | plain-language description |
| GET | `/healthz` | public | liveness |

Writes are validated (curef/fv regex), rate-limited per IP (120/min), and body
is capped at 4 KB. The `x-tcl-key` is anti-spam only — it ships in the
open-source client, so it is not a secret.

## Config (environment)

| var | default | |
|-----|---------|--|
| `PORT` | `8788` | |
| `HOST` | `127.0.0.1` | localhost, meant to sit behind a tunnel/reverse proxy |
| `DATA_DIR` | `./data` | `curefs.json` (aggregate) + `events.jsonl` (raw log) |
| `TCL_CUREF_KEY` | — | required for writes |
| `FLUSH_MS` | `2000` | debounce for the aggregate flush |

## Deployment (the beast)

Runs on `74.208.90.189` as a hardened systemd service (`tcl-curef`) under the
unprivileged `tclcuref` user, bound to `127.0.0.1:8788`, exposed publicly via a
Cloudflare Zero Trust tunnel at **https://tcl.tunnel-me.online**.

```bash
# from a machine with the deploy key:
scp -i <key> curef-server/server.js root@74.208.90.189:/tmp/tcl-curef-server.js
scp -i <key> curef-server/deploy.sh  root@74.208.90.189:/tmp/deploy.sh
ssh -i <key> root@74.208.90.189 'TCL_CUREF_KEY=<key> bash /tmp/deploy.sh'
```

Service ops:

```bash
systemctl status tcl-curef
journalctl -u tcl-curef -f
systemctl restart tcl-curef
```

Data lives in `/var/lib/tcl-curef/`.

## Client opt-out

Sharing is disclosed on first run and is opt-out:

```
tcl-fw sharing            # status + exactly what's recorded
tcl-fw sharing --off      # stop sharing
tcl-fw sharing --on       # resume
```

The GUI shows the same notice once and a checkbox at the bottom of the window.
Submissions are fire-and-forget: if the server is unreachable the tool proceeds
normally and simply skips the record.
