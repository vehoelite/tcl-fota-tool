"""
cli.py — the `tcl-fw` command-line interface (Typer + Rich).

Commands:
  pull     auto-CUREF -> resolve -> download + decrypt -> flashable images
  list     resolve a device and list every partition, size and name
  decrypt  decrypt a local encrypted-header blob
  devices  show known devices / detect a plugged-in phone
"""

from __future__ import annotations

import os
from typing import Optional

import typer
from rich.console import Console
from rich.progress import (BarColumn, DownloadColumn, Progress, SpinnerColumn,
                           TextColumn, TransferSpeedColumn)
from rich.table import Table

from . import __version__, adb, devices, flashpack, fota, naming, puller, sharing, templates
from .crypto import decrypt_header, key_hex

app = typer.Typer(
    add_completion=False,
    help="Pull and decrypt official TCL (MediaTek) FOTA firmware.",
    rich_markup_mode="rich",
)
console = Console()

CREDIT = "Header decryption by [bold]Littlenine Ennea[/] (github.com/LittlenineEnnea)"


def _banner() -> None:
    console.print(f"[bold cyan]tcl-fw[/] [dim]v{__version__}[/]  ·  {CREDIT}")


def _version_cb(value: bool):
    if value:
        console.print(f"tcl-fw {__version__}")
        console.print(f"universal header key: {key_hex()}")
        console.print(CREDIT)
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_cb, is_eager=True,
        help="Show version + credit and exit."),
):
    """TCL FOTA firmware puller + .mbn header decryptor."""
    # First-run disclosure for community sharing — shown once, never hidden.
    if sharing.notice_pending():
        console.print(sharing.NOTICE)
        sharing.mark_notice_shown()


# ── helpers ─────────────────────────────────────────────────────────────────

def _device_fv_for(curef: str) -> Optional[str]:
    """Read the current firmware version off a plugged-in phone whose curef
    matches — so OTA gets a real fv without the user typing anything."""
    if not adb.available():
        return None
    want = curef.lower().removesuffix("-v")
    try:
        for serial in adb.list_serials():
            dev = adb.read_device(serial)
            if dev.curef and dev.fv and dev.curef.lower().removesuffix("-v") == want:
                return dev.fv
    except Exception:
        pass
    return None


def _auto_curef(curef: Optional[str]) -> tuple[str, Optional[str], Optional[str]]:
    """Determine the curef: explicit arg, else a plugged-in phone. Returns
    (curef, tv_hint, fw_hint) — the fw_hint (fv) is pulled from the device
    build when a matching phone is connected, whether or not curef was typed."""
    if curef:
        fv = _device_fv_for(curef)
        if fv:
            console.print(f"[green]Read firmware version[/] [bold]{fv}[/] from the phone.")
        return curef, None, fv
    if adb.available():
        dev = adb.detect()
        if dev and dev.curef:
            console.print(f"[green]Detected device[/]: {dev.name or dev.model} "
                          f"→ curef [bold]{dev.curef}[/]")
            return dev.curef, None, dev.fv
    raise typer.BadParameter(
        "no curef given and no phone detected. Pass a curef "
        "(adb shell getprop ro.tct.curef) or plug in a phone with USB debugging.")


def _resolve_or_die(curef: str, tv: Optional[str], fw_id: Optional[str],
                    mode: int = 4, fv: str = "000000"):
    curef, tv, fw_id = devices.resolve(curef, tv, fw_id, mode=mode, fv=fv or "000000")
    if not (tv and fw_id):
        if mode == 4:
            # A FULL (mode 4) resolve that returns nothing usually means the
            # server recognizes the curef but publishes no whole-firmware image
            # for it — many variants only ever get OTA deltas. Point the user at
            # mode 2 rather than implying the curef is wrong.
            console.print(
                f"[yellow]No FULL image is published for[/] {curef}[yellow].[/] "
                "That's normal — many devices only get OTA updates.\n"
                "Try an [bold]OTA[/] check instead: [bold]--mode 2[/]. With a phone "
                "plugged in the firmware version is read automatically; otherwise add "
                f"[bold]--fv <your version>[/].\n"
                f"E.g. [bold]tcl-fw list {curef} --mode 2[/]."
            )
        elif not fv or fv == "000000":
            # OTA with no real firmware version — the server can't compute a
            # delta from a placeholder. Usual cause, not a bad curef.
            console.print(
                f"[yellow]OTA needs this device's current firmware version.[/] "
                f"None was found for {curef} — plug the phone in (it's read "
                "automatically) or pass [bold]--fv <your version>[/] "
                "(from [bold]adb shell getprop ro.tct.sys.ver[/], rearranged)."
            )
        else:
            console.print(
                f"[yellow]No OTA update offered for[/] {curef} [yellow]at firmware[/] "
                f"{fv}. The phone may already be on the latest version, or the FV "
                "may be wrong."
            )
        raise typer.Exit(1)
    return curef, tv, fw_id


# ── commands ────────────────────────────────────────────────────────────────

@app.command("list")
def list_cmd(
    curef: Optional[str] = typer.Argument(None, help="Device curef (auto-detects if omitted)."),
    tv: Optional[str] = typer.Option(None, "--tv"),
    fw_id: Optional[str] = typer.Option(None, "--fw-id"),
    fv: Optional[str] = typer.Option(None, "--fv", help="Current firmware version (auto-detected if a phone is plugged in). Required for OTA (--mode 2) on a typed curef."),
    mode: int = typer.Option(4, "--mode", help="FOTA mode (4=full image; try 2 if a device serves nothing on 4)."),
):
    """List every partition for a device: name, size, and download URL."""
    _banner()
    curef, _, fvh = _auto_curef(curef)
    fvh = fv or fvh
    curef, tv, fw_id = _resolve_or_die(curef, tv, fw_id, mode=mode, fv=fvh)
    sharing.submit(curef, fvh, mode, tv, fw_id)
    info = fota.request_download(curef, tv, fw_id, mode=mode, fv=fvh or "AAA000")

    known = devices.lookup(curef)
    console.print(f"\n[bold]{curef}[/]  {known.name if known else ''}")
    console.print(f"tv=[cyan]{tv}[/]  fw_id=[cyan]{fw_id}[/]  "
                  f"{len(info.files)} files   body={info.slave}  header={info.encslave}\n")

    with console.status("Probing bodies + resolving names…"):
        plan = puller.build_plan(curef, info, mode=mode)

    table = Table(show_lines=False, header_style="bold")
    table.add_column("FILE_NAME", style="green", no_wrap=True)
    table.add_column("FILE_ID", style="dim")
    table.add_column("SIZE", justify="right")
    table.add_column("SOURCE")
    # Sort by real (probed) body size, largest first; header parts (size<=0) last.
    for f in sorted(info.files, key=lambda x: -(plan.sizes.get(x.file_id, -1))):
        bs = plan.sizes.get(f.file_id, -1)
        is_small = bs <= 0
        nm = plan.names.get(f.file_id)
        if not nm:
            nm = ("[in enc header]" if is_small
                  else naming.magic_name(fota.body_head(info.slave, f.rel_url))[0])
        src = "[cyan]header[/]" if is_small else "body"
        size = "[dim]—[/]" if is_small else f"{bs:,}"
        table.add_row(nm, f.file_id, size, src)
    console.print(table)
    console.print("\n[dim]next:[/]  tcl-fw pull "
                  f"{curef}   [dim]# complete package[/]   |   "
                  f"tcl-fw pull {curef} --small   [dim]# just lk/preloader/…[/]")


@app.command()
def pull(
    curef: Optional[str] = typer.Argument(None, help="Device curef (auto-detects if omitted)."),
    tv: Optional[str] = typer.Option(None, "--tv"),
    fw_id: Optional[str] = typer.Option(None, "--fw-id"),
    outdir: Optional[str] = typer.Option(None, "--out", "-o", help="Output directory."),
    small: bool = typer.Option(False, "--small", help="Only the small header-encrypted parts (lk/preloader/… fast)."),
    only: Optional[str] = typer.Option(None, "--only", help="Comma list of partition names to pull."),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip SHA-1 verification of bodies."),
    pack_after: bool = typer.Option(False, "--pack", help="After pulling, rename to real partition names + write an SP Flash Tool scatter.txt."),
    fv: Optional[str] = typer.Option(None, "--fv", help="Current firmware version (auto-detected if a phone is plugged in). Required for OTA (--mode 2) on a typed curef."),
    mode: int = typer.Option(4, "--mode", help="FOTA mode (4=full image; try 2 if a device serves nothing on 4)."),
):
    """Download + decrypt a device's service package into flashable images."""
    _banner()
    curef, _, fvh = _auto_curef(curef)
    fvh = fv or fvh
    curef, tv, fw_id = _resolve_or_die(curef, tv, fw_id, mode=mode, fv=fvh)
    sharing.submit(curef, fvh, mode, tv, fw_id)
    info = fota.request_download(curef, tv, fw_id, mode=mode, fv=fvh or "AAA000")

    out = outdir or f"pkg_{curef.replace('/', '_')}"
    os.makedirs(out, exist_ok=True)
    console.print(f"\n[bold]{curef}[/]  tv={tv} fw_id={fw_id}  "
                  f"{len(info.files)} files → [bold]{out}/[/]\n")

    with console.status("Probing bodies + resolving names…"):
        plan = puller.build_plan(curef, info, mode=mode)

    want = {w.strip().lower() for w in only.split(",")} if only else None
    todo = []
    for f in info.files:
        bs = plan.sizes.get(f.file_id, -1)
        is_small = bs <= 0
        if small and not is_small:
            continue
        if want:
            nm = (plan.names.get(f.file_id) or "").lower()
            stem = os.path.splitext(nm)[0]
            if not any(stem == w or stem.startswith(w) for w in want):
                continue
        todo.append(f)

    results = []
    progress = Progress(
        SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
        BarColumn(), DownloadColumn(), TransferSpeedColumn(),
        console=console, transient=True,
    )
    with progress:
        for f in todo:
            nm = plan.names.get(f.file_id) or f.file_id
            bs = plan.sizes.get(f.file_id, -1)
            task = progress.add_task(nm, total=bs if bs > 0 else None)

            def cb(got, total, _t=task):
                progress.update(_t, completed=got, total=total or None)

            r = puller.pull_one(plan, f, out, on_progress=cb, verify=not no_verify)
            results.append(r)
            progress.remove_task(task)
            if r.error:
                console.print(f"  [red]![/] {r.name}  ({r.error})")
            else:
                tag = ("DEC " if r.kind == "header" else "BODY")
                vmark = "" if r.verified is None else (" [green]✓[/]" if r.verified else " [red]✗ checksum[/]")
                console.print(f"  [dim]{tag}[/] {r.name}  [dim]{r.size:,} B[/]{vmark}")

    mpath = puller.write_manifest(curef, plan, results, out)
    ok = sum(1 for r in results if not r.error)
    dec = sum(1 for r in results if r.kind == "header" and not r.error)
    console.print(f"\n[green]✓[/] {ok}/{len(todo)} files → {out}/  "
                  f"[dim]({dec} decrypted from headers)[/]")
    console.print(f"[dim]manifest: {mpath}[/]")

    if pack_after:
        console.print()
        _run_pack(out)


def _run_pack(outdir: str, dry_run: bool = False, min_conf: float = 0.7) -> None:
    """Map images to scatter partitions, rename the confident ones, and write an
    SP Flash Tool scatter.txt. Shared by `pack` and `pull --pack`."""
    result = flashpack.build(outdir)
    if not result:
        console.print("[yellow]No MTK scatter found[/] in this folder — "
                      "nothing to pack (device may use the GOTU .sca format).")
        return
    conf = sorted((m for m in result.matches if m.part and m.confidence >= min_conf),
                  key=lambda m: -m.probe.size)
    low = sorted((m for m in result.matches if m.part and m.confidence < min_conf),
                 key=lambda m: -m.probe.size)

    tbl = Table(header_style="bold", title=f"{result.doc.platform} · {result.doc.project}")
    tbl.add_column("current file", style="dim", no_wrap=True)
    tbl.add_column("→ partition", style="green", no_wrap=True)
    tbl.add_column("conf", justify="right")
    tbl.add_column("how")
    for m in conf:
        tbl.add_row(m.probe.fname, m.new_name, f"{m.confidence:.2f}", m.how)
    console.print(tbl)

    path = flashpack.apply(outdir, result, dry_run=dry_run, min_confidence=min_conf)
    verb = "would rename" if dry_run else "renamed"
    console.print(f"[green]✓[/] {verb} {len(conf)} partitions; "
                  f"scatter → [bold]{os.path.basename(path)}[/]")
    if low:
        console.print(f"\n[yellow]{len(low)} low-confidence[/] (left as-is — verify by hand):")
        for m in low:
            console.print(f"  [dim]{m.probe.fname}[/]  ~  {m.part.file_name}  "
                          f"[dim]({m.confidence:.2f} {m.how})[/]")
    if result.unmapped:
        console.print(f"[dim]unmapped: {', '.join(p.fname for p in result.unmapped)}[/]")
    console.print("\n[dim]Flash with SP Flash Tool (load the scatter) or mtkclient.[/]")


@app.command()
def pack(
    pkgdir: str = typer.Argument(..., help="A pulled service-pack folder (pkg_<curef>/)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the mapping; rename nothing."),
    min_conf: float = typer.Option(0.7, "--min-confidence", help="Only rename at/above this confidence."),
):
    """Rename a pulled folder's images to real partition names and emit an
    SP Flash Tool scatter.txt (uses the MTK scatter that shipped in the pack)."""
    _banner()
    if not os.path.isdir(pkgdir):
        console.print(f"[red]Not a folder:[/] {pkgdir}")
        raise typer.Exit(1)
    _run_pack(pkgdir, dry_run=dry_run, min_conf=min_conf)


@app.command()
def decrypt(
    blob: str = typer.Argument(..., help="Path to an encrypted-header blob."),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Output path (default: <blob>.dec)."),
):
    """Decrypt a single local encrypted-header blob."""
    with open(blob, "rb") as f:
        enc = f.read()
    img = decrypt_header(enc)
    name, ext = naming.magic_name(img)
    dest = out or (blob + ".dec")
    with open(dest, "wb") as f:
        f.write(img)
    console.print(f"{blob} → [green]{dest}[/]  "
                  f"({len(img):,} B, looks like [bold]{name}[/], starts {img[:8].hex()})")


def devices_cmd(
    detect: bool = typer.Option(False, "--detect", help="Probe for a plugged-in phone."),
):
    """List known devices, or detect a connected phone (--detect)."""
    if detect:
        if not adb.available():
            console.print("[yellow]adb not found[/] — set TCL_FW_ADB or add adb to PATH.")
            raise typer.Exit(1)
        dev = adb.detect()
        if not dev:
            console.print("[yellow]No authorized device connected.[/]")
            raise typer.Exit(1)
        console.print(f"[green]Connected[/]: {dev.name or dev.model}")
        console.print(f"  curef: [bold]{dev.curef}[/]")
        console.print(f"  fv:    {dev.fv}")
        return

    table = Table(header_style="bold")
    table.add_column("CUREF", style="cyan")
    table.add_column("TV", style="dim")
    table.add_column("FW_ID", style="dim")
    table.add_column("NAME")
    for d in devices.catalog().values():
        table.add_row(d.curef, d.tv or "?", d.fw_id or "?", d.name)
    console.print(table)


# Typer names the command from the function; expose it as `devices`.
app.command("devices")(devices_cmd)


@app.command("templates")
def templates_cmd(
    show_all: bool = typer.Option(False, "--all", "-a", help="Show every recorded release, not just the latest per device."),
):
    """List validated firmware templates and their release history.

    Each device carries the builds we've seen for it; a build first seen within
    the last few weeks is tagged [bold green]NEW[/]. Run [bold]tcl-fw refresh[/]
    to check the server for newer ones."""
    tpls = templates.load()
    if not tpls:
        console.print("[yellow]No templates yet.[/] Run [bold]tcl-fw refresh[/] to build the list.")
        return

    table = Table(header_style="bold")
    table.add_column("CUREF", style="cyan", no_wrap=True)
    table.add_column("MODE", justify="center", style="dim")
    table.add_column("TV", style="dim")
    table.add_column("FW_ID", style="dim")
    table.add_column("FIRST SEEN", style="dim")
    table.add_column("")               # NEW tag
    table.add_column("NAME")

    for t in sorted(tpls, key=lambda t: (t.name or t.curef).lower()):
        rels = sorted(t.releases, key=lambda r: r.first_seen, reverse=True)
        if not show_all:
            rels = rels[:1]
        for i, r in enumerate(rels):
            tag = "[bold green]NEW[/]" if r.is_new() else ""
            table.add_row(
                t.curef if i == 0 else "",
                str(t.mode) if i == 0 else "",
                r.tv, r.fw_id, r.first_seen, tag,
                (t.name if i == 0 else ""),
            )
    console.print(table)
    console.print("\n[dim]Downloads always resolve the current build live; "
                  "this list is a validated record. `tcl-fw refresh` checks for newer.[/]")


@app.command("refresh")
def refresh_cmd(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Check for new releases but don't write the file."),
):
    """Re-check every template against the live server and record new releases."""
    _banner()
    tpls = templates.load()
    if not tpls:
        console.print("[yellow]No templates to refresh.[/]")
        raise typer.Exit(1)

    with console.status(f"Checking {len(tpls)} devices for new firmware…"):
        added = templates.refresh(tpls)

    if added:
        console.print(f"[bold green]{len(added)} new release(s):[/]")
        for curef, tv, fw in added:
            console.print(f"  [cyan]{curef}[/]  tv=[bold]{tv}[/] fw_id={fw}")
    else:
        console.print("[green]Up to date[/] — no new firmware since the last check.")

    if dry_run:
        console.print("[dim](--dry-run: nothing written)[/]")
    else:
        templates.save(tpls)


@app.command("sharing")
def sharing_cmd(
    on: bool = typer.Option(False, "--on", help="Turn community device sharing ON."),
    off: bool = typer.Option(False, "--off", help="Turn community device sharing OFF."),
):
    """Show or change community device-ID sharing (opt-out, nothing personal)."""
    if on and off:
        console.print("[red]Pick one of --on / --off.[/]")
        raise typer.Exit(1)
    if on or off:
        sharing.set_enabled(on)
        console.print(f"Community device sharing is now [bold]{'ON' if on else 'OFF'}[/].")
        return
    console.print(sharing.status_text())


if __name__ == "__main__":
    app()
