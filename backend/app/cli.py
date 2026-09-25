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


def _progress(message: str, *, quiet: bool) -> None:
    """Progress goes to stderr so stdout stays pipeable.

    Deliberately ASCII. Progress lines are functional rather than decorative,
    and a legacy console renders them as escape sequences otherwise.
    """
    if not quiet:
        stamp = time.strftime("%H:%M:%S")
        print(f"{stamp} | {message}", file=sys.stderr, flush=True)


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

    selection = "explicit module list" if args.modules else f"profile {scan_type.value}"
    _progress(f"Target {domain} - {selection} - {len(tools)} module(s)", quiet=args.quiet)

    import uuid

    from app.services import triage as triage_service

    scan_id = f"cli-{uuid.uuid4().hex[:12]}"
    started = time.monotonic()
    all_findings: list[dict] = []
    tool_results: dict[str, object] = {}

    for index, (name, fn) in enumerate(tools, start=1):
        _progress(f"[{index}/{len(tools)}] {name}", quiet=args.quiet)
        try:
            findings = fn(domain) or []
        except Exception as exc:  # noqa: BLE001 — one module must not end the scan
            _progress(f"    {name} failed: {type(exc).__name__}: {exc}", quiet=args.quiet)
            tool_results[name] = {"findings": 0, "status": f"error: {type(exc).__name__}"}
            continue
        tool_results[name] = {"findings": len(findings), "status": "ok"}
        all_findings.extend(findings)

    if danger_session is not None:
        from app.tasks.vulnscan.danger.pipeline import danger_stages

        for name, stage in danger_stages(danger_session):
            _progress(f"[danger] {name}", quiet=args.quiet)
            try:
                findings = stage() or []
            except Exception as exc:  # noqa: BLE001
                _progress(f"    {name} failed: {type(exc).__name__}", quiet=args.quiet)
                tool_results[name] = {"findings": 0, "status": f"error: {type(exc).__name__}"}
                continue
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

    _progress("Applying triage decisions", quiet=args.quiet)
    try:
        triage_service.apply_to_report(report)
        correlation_input = dict(report)
        correlation_input["findings"] = triage_service.active_findings(all_findings)
    except Exception:  # noqa: BLE001
        report.setdefault("triage_summary", {})
        correlation_input = report

    _progress("Correlating attack paths", quiet=args.quiet)
    try:
        from app.services.attack_paths import build_attack_paths

        report["attack_paths"] = build_attack_paths(correlation_input)
    except Exception:  # noqa: BLE001
        report["attack_paths"] = []

    return report, 0


def _render(report: dict, fmt: str) -> bytes:
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


def main(argv: list[str] | None = None) -> int:
    _use_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)

    _apply_overrides(args)

    # Imported only now, so the overrides above are visible to settings.
    if args.list_modules:
        return _list_modules()

    if not args.target:
        parser.print_usage(file=sys.stderr)
        print("error: a target is required (or use --list-modules)", file=sys.stderr)
        return 2

    if args.format == "pdf" and not args.output:
        print("error: --format pdf requires --output", file=sys.stderr)
        return 2

    report, code = _run_scan(args)
    if code:
        return code

    rendered = _render(report, args.format)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rendered)
        _progress(f"Report written to {path} ({len(rendered)} bytes)", quiet=args.quiet)
    else:
        sys.stdout.buffer.write(rendered)
        sys.stdout.buffer.flush()

    counts = report.get("severity_counts") or {}
    _progress(
        "Done — "
        + ", ".join(f"{sev}:{counts.get(sev, 0)}" for sev in
                    ("critical", "high", "medium", "low", "info")),
        quiet=args.quiet,
    )
    return _exit_code_for(report, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
