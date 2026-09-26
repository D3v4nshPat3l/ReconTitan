"""Command-line interface for ReconTitan.

The web UI is the primary interface and remains so. A CLI exists because some
things the UI cannot do are ordinary requests:

* run a scan from cron, or from a CI job, without a browser or an API call
* pipe a report into grep, jq or a diff against last week's
* run on a headless host where opening a browser is not an option

It shares the scan pipeline with the API rather than reimplementing it, so a
finding here is the same finding the report shows, produced by the same code.

Per-run overrides are set into the environment before the settings module is
imported. That ordering is not incidental -- settings are read once at import
-- so every function that touches configuration is imported lazily inside
``main``. Moving those imports to the top of the file would silently break
every override flag.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROFILES = {
    "recon": "recon_only",
    "osint": "osint_only",
    "vuln": "vuln_only",
    "full": "full",
    "danger": "danger",
}

FORMATS = ("txt", "json", "html", "pdf")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recontitan",
        description=(
            "External attack surface assessment. Scans a domain and writes a "
            "report in which every finding carries the evidence behind it."
        ),
        epilog=(
            "Only scan systems you own or have explicit written permission to "
            "test. Danger Mode sends real attack traffic and additionally "
            "requires the typed acknowledgement phrase."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", nargs="?", help="Domain or IP to scan, e.g. example.com")
    parser.add_argument(
        "-p", "--profile", choices=sorted(PROFILES), default="full",
        help="Scan profile (default: full)",
    )
    parser.add_argument(
        "-m", "--modules",
        help="Run only these modules, comma-separated. Overrides --profile.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write the report here. Default: stdout for txt/json, required for pdf.",
    )
    parser.add_argument(
        "-f", "--format", choices=FORMATS, default="txt",
        help="Report format (default: txt)",
    )

    scan = parser.add_argument_group("scan tuning (override .env for this run only)")
    scan.add_argument("-d", "--dns", help="Custom DNS resolvers, comma-separated")
    scan.add_argument("-T", "--timeout", type=int, help="Per-request timeout in seconds")
    scan.add_argument("-w", "--wordlist", help="Path to a directory-enumeration wordlist")
    scan.add_argument(
        "--wordlist-size", choices=("small", "common", "big"),
        help="Which bundled wordlist to use when --wordlist is not given",
    )
    scan.add_argument(
        "-e", "--extensions",
        help="File extensions to append during enumeration, e.g. php,bak,txt",
    )
    scan.add_argument("--dir-threads", type=int, help="Directory enumeration threads")
    scan.add_argument("--port-threads", type=int, help="Built-in port scanner threads")
    scan.add_argument("--crawl-pages", type=int, help="Maximum pages to crawl")
    scan.add_argument("--wayback-limit", type=int, help="Maximum archived URLs to retrieve")
    scan.add_argument(
        "--no-crawl", action="store_true", help="Skip the site crawl",
    )
    scan.add_argument(
        "--no-dir-enum", action="store_true", help="Skip directory enumeration",
    )
    scan.add_argument(
        "--no-extended-dns", action="store_true",
        help="Query only the core DNS record types instead of the full sweep",
    )
    scan.add_argument(
        "--allow-private", action="store_true",
        help="Permit private or internal targets. For a local lab only.",
    )

    danger = parser.add_argument_group("danger mode")
    danger.add_argument(
        "--danger-ack", metavar="PHRASE",
        help=(
            "Typed authorisation phrase, required for --profile danger. "
            "The exact phrase is published by --list-modules."
        ),
    )

    output = parser.add_argument_group("output")
    output.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    output.add_argument(
        "--no-color", action="store_true",
        help="Disable colour. NO_COLOR in the environment does the same.",
    )
    output.add_argument(
        "--no-banner", action="store_true", help="Skip the launch banner",
    )
    output.add_argument(
        "--list-modules", action="store_true",
        help="List available modules and profiles, then exit",
    )
    output.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low"),
        help="Exit non-zero when a finding at or above this severity is present",
    )
    return parser


def _apply_overrides(args: argparse.Namespace) -> None:
    """Translate flags into environment variables.

    Must run before anything imports ``app.config``.
    """
    overrides: dict[str, str] = {}
    if args.dns:
        overrides["DNS_SERVERS"] = args.dns
    if args.timeout:
        overrides["DIR_ENUM_TIMEOUT"] = str(args.timeout)
        overrides["CRAWLER_TIMEOUT"] = str(args.timeout)
        overrides["DNS_RECORD_TIMEOUT"] = str(args.timeout)
        overrides["SUBDOMAIN_SOURCE_TIMEOUT"] = str(args.timeout)
    if args.wordlist:
        overrides["DIR_ENUM_WORDLIST"] = args.wordlist
    if args.wordlist_size:
        overrides["DIR_ENUM_WORDLIST_SIZE"] = args.wordlist_size
    if args.extensions:
        overrides["DIR_ENUM_EXTENSIONS"] = args.extensions
    if args.dir_threads:
        overrides["DIR_ENUM_THREADS"] = str(args.dir_threads)
    if args.port_threads:
        overrides["PORT_SCAN_THREADS"] = str(args.port_threads)
    if args.crawl_pages:
        overrides["CRAWLER_MAX_PAGES"] = str(args.crawl_pages)
    if args.wayback_limit:
        overrides["WAYBACK_URL_LIMIT"] = str(args.wayback_limit)
    if args.no_crawl:
        overrides["CRAWLER_ENABLED"] = "false"
    if args.no_dir_enum:
        overrides["DIR_ENUM_ENABLED"] = "false"
    if args.no_extended_dns:
        overrides["DNS_EXTENDED_RECORDS"] = "false"
    if args.allow_private:
        overrides["ALLOW_PRIVATE_TARGETS"] = "true"
    # Scans from a terminal are synchronous by nature: there is no worker to
    # hand the job to and nobody to poll for it.
    overrides.setdefault("ASYNC_SCANS_ENABLED", "false")
    os.environ.update(overrides)


def _use_utf8_streams() -> None:
    """Ask the console for UTF-8, and do not depend on getting it.

    Python picks the legacy code page for the console on Windows, and its
    stderr falls back to ``backslashreplace``. Progress lines written through
    it arrived as the literal text ``\\u2502`` with question marks where the
    dashes were -- readable output turned into escape sequences. Terminals
    that understand UTF-8 (Git Bash, Windows Terminal) get it after this;
    the ones that do not are handled by keeping the progress glyphs ASCII
    below, so both cases stay legible.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


#: Progress is drawn on stderr, always. A report piped into grep or jq must
#: contain the report and nothing else, and progress on stdout would put the
#: scan log inside the data.
_ui: dict = {"theme": None, "quiet": False, "count": 0, "total": 0}


def _theme():
    """The stderr theme, built once.

    Built against stderr rather than stdout on purpose: when the report is
    piped, stdout is not a terminal and loses its colour, while the progress
    the operator is watching is still going to a terminal and keeps it.
    """
    if _ui["theme"] is None:
        from app.services.terminal import Theme, enable_windows_vt

        enable_windows_vt()
        _ui["theme"] = Theme(sys.stderr, color=_ui.get("color"))
    return _ui["theme"]


def _say(message: str = "") -> None:
    if not _ui["quiet"]:
        print(message, file=sys.stderr, flush=True)


def _banner() -> None:
    """The launch banner, on stderr.

    Same lettering the setup scripts print, so the CLI and the installer look
    like one tool rather than two. Suppressed by --quiet and --no-banner, and
    on stderr so it never lands in a piped report.
    """
    if _ui["quiet"] or _ui.get("no_banner"):
        return
    from app.config import settings
    from app.services.terminal_report import render_banner

    print(render_banner(_theme(), settings.APP_VERSION), file=sys.stderr, flush=True)


def _progress(message: str, *, quiet: bool | None = None) -> None:
    """A timestamped status line."""
    if quiet if quiet is not None else _ui["quiet"]:
        return
    t = _theme()
    stamp = t.s(time.strftime("%H:%M:%S"), "dim", "grey")
    print(f"  {stamp}  {message}", file=sys.stderr, flush=True)


def _module_line(name: str, *, index: int, total: int, elapsed: float,
                 findings: int = 0, error: str = "") -> None:
    """One aligned row per module, with its own outcome.

    The alignment is the point. A scan runs thirty modules and the operator is
    scanning the column, not reading the lines -- a row that shifts left or
    right for a longer name defeats that.
    """
    if _ui["quiet"]:
        return
    t = _theme()
    position = t.s(f"[{index:>2}/{total}]", "dim", "grey")
    if error:
        glyph, colour, detail = t.g("fail"), "red", error
    elif findings:
        glyph, colour, detail = t.g("ok"), "green", f"{findings} finding(s)"
    else:
        glyph, colour, detail = t.g("skip"), "grey", "no findings"
    print(
        f"  {position} {t.s(glyph, colour)}  {name.ljust(24)}"
        f"{t.s(f'{elapsed:>6.1f}s', 'dim', 'grey')}   {t.s(detail, colour)}",
        file=sys.stderr, flush=True,
    )


def _step(message: str) -> None:
    """A post-scan pipeline step.

    Kept visually distinct from the module rows above it: those report a
    module's outcome, these report work the scanner is doing to the results
    it already has. Using the same shape for both would suggest the triage
    pass is another scanner.
    """
    if _ui["quiet"]:
        return
    t = _theme()
    print(f"  {t.s(t.g('arrow'), 'dim', 'grey')}  {t.s(message, 'dim', 'grey')}",
          file=sys.stderr, flush=True)


def _preflight_panel(domain: str, scan_type, tools, args) -> None:
    """What this run is about to do, before it does any of it.

    A scan is minutes of waiting during which the only visible thing is a
    hostname. Stating the target, the resolved address, the module count and
    the Danger Mode state up front turns "is this the right target" into a
    question answered before the waiting starts rather than after.
    """
    if _ui["quiet"]:
        return
    import platform

    from app.config import settings
    from app.services.terminal import Theme  # noqa: F401 — imported for typing clarity

    t = _theme()

    address = ""
    try:
        from app.targeting import resolve_target_addresses

        resolved = resolve_target_addresses(domain)
        address = resolved[0] if resolved else ""
    except Exception:  # noqa: BLE001 — cosmetic; the modules validate properly
        address = ""

    target = t.s(domain, "bold", "white")
    if address:
        target += t.s(f"  {t.g('arrow')} {address}", "grey")

    selection = (
        t.s("explicit module list", "yellow") if args.modules
        else f"{scan_type.value}"
    )
    danger = (
        t.s("UNLOCKED", "bold", "red") if scan_type.value == "danger"
        else t.s("locked", "green")
    )

    rows = [
        ("Target", target),
        ("Profile", f"{selection}   {t.s(f'{len(tools)} modules', 'grey')}"),
        ("Danger Mode", danger),
        ("Version", t.s(settings.APP_VERSION, "grey")),
        ("Python", t.s(platform.python_version(), "grey")),
    ]
    if settings.DNS_SERVERS:
        rows.append(("Resolvers", t.s(", ".join(settings.DNS_SERVERS), "grey")))

    for line in t.panel("RUN", rows, style="cyan"):
        _say(line)
    _say("  " + t.s("Only scan systems you own or have written permission to test.", "dim", "grey"))
    _say()


def _list_modules() -> int:
    from app.config import settings
    from app.services.capabilities import SCAN_PROFILES, TOOL_GROUPS, runtime_report
    from app.services.danger_mode import danger_mode_metadata

    print("Profiles:")
    for key, profile in SCAN_PROFILES.items():
        flag = next((f for f, v in PROFILES.items() if v == key), key)
        print(f"  {flag:<8} ({key})  {profile['name']}")
    print()

    print("Modules by group:")
    for group, tools in TOOL_GROUPS.items():
        print(f"  {group}:")
        for tool in tools:
            print(f"    - {tool}")
    print()

    runtime = runtime_report()
    if runtime["binary_modules_unavailable"]:
        print("Modules whose binary is not installed here (they will report as skipped):")
        for tool in runtime["binary_modules_unavailable"]:
            print(f"  - {tool}")
        print()

    metadata = danger_mode_metadata()
    print(f"Danger Mode enabled : {settings.ALLOW_DANGER_MODE}")
    phrase = metadata.get("acknowledgement_phrase") or metadata.get("phrase")
    if phrase:
        print(f"Acknowledgement     : {phrase!r}  (pass via --danger-ack)")
    return 0


def _run_scan(args: argparse.Namespace) -> tuple[dict, int]:
    """Execute the scan and return (report, exit_code)."""
    from app.models.schemas import ScanType
    from app.routers.test_scan import _selected_tools
    from app.targeting import validate_scan_target

    ok, domain, error = validate_scan_target(args.target, resolve_dns=False)
    if not ok:
        print(f"error: {error}", file=sys.stderr)
        return {}, 2

    scan_type = ScanType(PROFILES[args.profile])
    tools = _selected_tools(scan_type)
    if args.modules:
        wanted = {name.strip() for name in args.modules.split(",") if name.strip()}
        # Every safe module, not only the ones this profile would have run:
        # -m is an explicit request and should not be silently narrowed by a
        # profile the caller did not mean to constrain it.
        every = _selected_tools(ScanType.FULL)
        tools = [(name, fn) for name, fn in every if name in wanted]
        unknown = wanted - {name for name, _ in every}
        if unknown:
            print(f"error: unknown module(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print("       run --list-modules to see what is available", file=sys.stderr)
            return {}, 2
        if not tools:
            print("error: no modules selected", file=sys.stderr)
            return {}, 2

    danger_session = None
    if scan_type is ScanType.DANGER:
        from app.services.danger_mode import (
            DangerSession, danger_mode_enabled, verify_acknowledgement,
        )

        if not danger_mode_enabled():
            print(
                "error: Danger Mode is disabled. Set ALLOW_DANGER_MODE=true and retry.",
                file=sys.stderr,
            )
            return {}, 3
        if not args.danger_ack or not verify_acknowledgement(args.danger_ack):
            print(
                "error: Danger Mode requires the exact acknowledgement phrase via "
                "--danger-ack. Run --list-modules to see it.",
                file=sys.stderr,
            )
            return {}, 3
        danger_session = DangerSession(domain)

    _preflight_panel(domain, scan_type, tools, args)

    import uuid

    from app.services import triage as triage_service

    scan_id = f"cli-{uuid.uuid4().hex[:12]}"
    started = time.monotonic()
    all_findings: list[dict] = []
    tool_results: dict[str, object] = {}

    t = _theme()
    _say("  " + t.s("SCANNING", "bold", "white"))
    _say()

    for index, (name, fn) in enumerate(tools, start=1):
        module_started = time.monotonic()
        try:
            findings = fn(domain) or []
        except Exception as exc:  # noqa: BLE001 — one module must not end the scan
            _module_line(
                name, index=index, total=len(tools),
                elapsed=time.monotonic() - module_started,
                error=f"{type(exc).__name__}: {exc}"[:48],
            )
            tool_results[name] = {"findings": 0, "status": f"error: {type(exc).__name__}"}
            continue
        _module_line(
            name, index=index, total=len(tools),
            elapsed=time.monotonic() - module_started, findings=len(findings),
        )
        tool_results[name] = {"findings": len(findings), "status": "ok"}
        all_findings.extend(findings)

    if danger_session is not None:
        from app.tasks.vulnscan.danger.pipeline import danger_stages

        stages = list(danger_stages(danger_session))
        _say()
        _say("  " + _theme().s("DANGER MODE STAGES", "bold", "red"))
        _say()
        for index, (name, stage) in enumerate(stages, start=1):
            stage_started = time.monotonic()
            try:
                findings = stage() or []
            except Exception as exc:  # noqa: BLE001
                _module_line(
                    name, index=index, total=len(stages),
                    elapsed=time.monotonic() - stage_started,
                    error=f"{type(exc).__name__}"[:48],
                )
                tool_results[name] = {"findings": 0, "status": f"error: {type(exc).__name__}"}
                continue
            _module_line(
                name, index=index, total=len(stages),
                elapsed=time.monotonic() - stage_started, findings=len(findings),
            )
            tool_results[name] = {"findings": len(findings), "status": "ok"}
            all_findings.extend(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in all_findings:
        severity = str(finding.get("severity", "info")).lower()
        severity_counts[severity if severity in severity_counts else "info"] += 1

    from app.config import settings

    report = {
        "scan_id": scan_id,
        "target": domain,
        "scan_type": scan_type.value,
        "version": settings.APP_VERSION,
        "status": "completed",
        "total_time_seconds": round(time.monotonic() - started, 2),
        "tools_run": len(tool_results),
        "tools_used": sorted(tool_results),
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "tool_results": tool_results,
        "findings": all_findings,
    }
    if args.modules:
        # -m overrides the profile, so reporting the profile name unqualified
        # would describe a scan that did not happen.
        report["module_selection"] = sorted(name for name, _ in tools)
    if danger_session is not None:
        report["danger_summary"] = danger_session.summary().model_dump(mode="json")

    _say()
    _step("applying triage decisions")
    try:
        triage_service.apply_to_report(report)
        correlation_input = dict(report)
        correlation_input["findings"] = triage_service.active_findings(all_findings)
    except Exception:  # noqa: BLE001
        report.setdefault("triage_summary", {})
        correlation_input = report

    _step("correlating attack paths")
    try:
        from app.services.attack_paths import build_attack_paths

        report["attack_paths"] = build_attack_paths(correlation_input)
    except Exception:  # noqa: BLE001
        report["attack_paths"] = []

    return report, 0


def _render(report: dict, fmt: str, *, rich: bool = False) -> bytes:
    """Render the report.

    ``rich`` picks the terminal renderer -- colour, a contents list, boxed
    findings. It is chosen only when the destination is a terminal somebody is
    looking at. A report written to a file or piped into another tool gets the
    plain renderer, because escape codes in a file are corruption and a
    contents list built for scrolling is noise in a diff.
    """
    if fmt == "json":
        return json.dumps(report, indent=2, default=str).encode("utf-8")
    if fmt == "pdf":
        from app.services.pdf_report import build_pdf_report

        return build_pdf_report(report)
    if fmt == "html":
        from app.services.text_report import render_text_report
        from html import escape

        body = escape(render_text_report(report))
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>ReconTitan — {escape(str(report.get('target', '')))}</title>"
            "<style>body{background:#0b0f14;color:#d7e0ea;font:13px/1.5 ui-monospace,"
            "SFMono-Regular,Menlo,Consolas,monospace;margin:0;padding:24px}"
            "pre{white-space:pre-wrap;word-wrap:break-word;margin:0}</style></head>"
            f"<body><pre>{body}</pre></body></html>"
        ).encode("utf-8")

    if rich:
        from app.services.terminal import Theme
        from app.services.terminal_report import render_terminal_report

        return render_terminal_report(report, Theme(sys.stdout, color=_ui.get("color"))).encode("utf-8")

    from app.services.text_report import render_text_report

    return render_text_report(report).encode("utf-8")


def _exit_code_for(report: dict, threshold: str | None) -> int:
    if not threshold:
        return 0
    order = ("critical", "high", "medium", "low")
    counts = report.get("severity_counts") or {}
    for severity in order[: order.index(threshold) + 1]:
        if counts.get(severity, 0):
            return 1
    return 0


def _fail(message: str, hint: str = "") -> None:
    """One consistent error shape, on stderr, in colour where there is one."""
    t = _theme()
    print(f"  {t.s(t.g('fail') + ' error', 'bold', 'red')}  {message}", file=sys.stderr)
    if hint:
        print(f"          {t.s(hint, 'grey')}", file=sys.stderr)


def _completion(report: dict, args) -> None:
    """The one-line verdict, after the report has been written.

    Repeated on stderr because the report may have gone to a file or down a
    pipe, and the operator watching the terminal should not have to open it
    to learn whether anything was found.
    """
    if _ui["quiet"]:
        return
    t = _theme()
    counts = report.get("severity_counts") or {}
    parts = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts.get(severity, 0)
        colour = t.severity_color(severity) if count else "grey"
        parts.append(t.s(f"{severity} {count}", "bold" if count else "dim", colour))

    _say()
    _say("  " + t.s(t.g("h") * (t.width - 2), "grey"))
    duration = t.s(f"{report.get('total_time_seconds', '?')}s", "grey")
    findings = t.s(f"{report.get('total_findings', 0)} findings", "grey")
    _say(f"  {t.s(t.g('ok') + ' scan complete', 'bold', 'green')}   {duration}   {findings}")
    _say("  " + "   ".join(parts))
    _say()


def main(argv: list[str] | None = None) -> int:
    _use_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)

    _ui["quiet"] = bool(args.quiet)
    _ui["no_banner"] = bool(args.no_banner)
    if args.no_color:
        _ui["color"] = False

    _apply_overrides(args)

    # Imported only now, so the overrides above are visible to settings.
    if args.list_modules:
        return _list_modules()

    if not args.target:
        _banner()
        parser.print_usage(file=sys.stderr)
        _fail("a target is required", "try:  recontitan example.com    or  --list-modules")
        return 2

    if args.format == "pdf" and not args.output:
        _fail("--format pdf requires --output", "e.g.  --format pdf --output report.pdf")
        return 2

    _banner()

    report, code = _run_scan(args)
    if code:
        return code

    # Colour and the contents list are for a terminal being read, not for a
    # file or a pipe. Deciding here rather than inside the renderer keeps the
    # rule in one place.
    from app.services.terminal import supports_color

    rich = (
        args.format == "txt"
        and not args.output
        and (False if args.no_color else supports_color(sys.stdout))
    )

    rendered = _render(report, args.format, rich=rich)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rendered)
        _completion(report, args)
        _step(f"report written to {path}  ({len(rendered):,} bytes)")
    else:
        sys.stdout.buffer.write(rendered)
        sys.stdout.buffer.flush()
        _completion(report, args)

    return _exit_code_for(report, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
