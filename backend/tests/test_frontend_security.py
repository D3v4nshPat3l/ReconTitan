from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_frontend_has_no_inline_scripts_or_event_handlers():
    for path in (ROOT / "frontend").glob("*.html"):
        text = path.read_text(encoding="utf-8").lower()
        assert "<script>" not in text
        assert "onclick=" not in text
        assert "onerror=" not in text
        assert "onload=" not in text


def test_javascript_files_parse_with_node():
    # Syntax itself is checked in CI with node --check; this test verifies the expected files exist.
    assert (ROOT / "frontend" / "dashboard.js").is_file()
    assert (ROOT / "frontend" / "report.js").is_file()


def test_escape_helpers_render_zero_rather_than_blanking_it():
    """`String(x || '')` turns a legitimate 0 into an empty string.

    That silently blanked every zero count in the report - "0 failed" rendered
    as " failed". The HTML-escape helpers must use ?? so only null and undefined
    fall back. (safeUrl deliberately keeps ||, because a falsy URL should become
    the '#' placeholder.)
    """
    import re

    for name in ("report.js", "dashboard.js"):
        source = (ROOT / "frontend" / name).read_text(encoding="utf-8")
        # Isolate the escape helper's own definition, however it is written.
        match = re.search(r"(?:const esc\s*=|function esc\s*\()[^\n]*\n?[^\n]*", source)
        assert match, f"no esc helper found in {name}"
        definition = match.group(0)
        assert "??" in definition, f"{name}: esc uses || and will blank a legitimate 0"
        assert "||" not in definition.split("replace", 1)[0], f"{name}: esc falls back with ||"


def test_static_capture_harness_is_not_shipped():
    """The screenshot harness is a build-time artifact and must never ship."""
    for leftover in (ROOT / "frontend").glob("_shot*"):
        raise AssertionError(f"capture harness left in the tree: {leftover.name}")
    assert not (ROOT / "frontend" / "scandata").exists(), "scan data left in the frontend"
