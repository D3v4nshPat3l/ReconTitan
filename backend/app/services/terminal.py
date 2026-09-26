"""Terminal primitives: colour, width, box drawing, and knowing when to stop.

Three rules shape everything here, and they are the reason this is a module
rather than escape codes sprinkled through the CLI.

**Colour is a property of the destination, not the program.** A report piped
into ``grep`` or redirected to a file must contain no escape codes at all, or
every downstream tool sees ``\\x1b[31m`` where it expected a word. Colour is
therefore decided per stream: progress on stderr can be coloured while the
report on stdout stays plain, which is exactly what should happen when
someone pipes the output.

**Width is discovered, never assumed.** Eighty columns is a guess that is
wrong in both directions: it wastes half a modern terminal and wraps badly in
a narrow one.

**Glyphs degrade.** A Windows console on a legacy code page cannot encode box
characters, and a traceback about encoding is a worse outcome than a report
drawn with dashes. Every decorative glyph has an ASCII counterpart, chosen
from what the stream can actually encode.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

#: Matches any ANSI escape sequence, so printable width can be measured on a
#: string that has already been coloured.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

RESET = "\x1b[0m"

#: Named styles. Kept small on purpose: a palette wide enough to encode six
#: meanings is a palette nobody can read at a glance.
STYLES: dict[str, str] = {
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "italic": "\x1b[3m",
    "underline": "\x1b[4m",
    "red": "\x1b[38;5;203m",
    "orange": "\x1b[38;5;215m",
    "yellow": "\x1b[38;5;222m",
    "green": "\x1b[38;5;114m",
    "cyan": "\x1b[38;5;80m",
    "blue": "\x1b[38;5;111m",
    "magenta": "\x1b[38;5;176m",
    "grey": "\x1b[38;5;245m",
    "white": "\x1b[38;5;253m",
    # Backgrounds, used only for severity badges, where the label has to be
    # legible at a glance without being read.
    "on_red": "\x1b[48;5;52m",
    "on_orange": "\x1b[48;5;94m",
    "on_yellow": "\x1b[48;5;58m",
    "on_blue": "\x1b[48;5;24m",
    "on_grey": "\x1b[48;5;238m",
}

#: Severity -> (foreground, badge background). Iterated worst-first everywhere,
#: because that is the order a reader needs them in.
SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "critical": ("red", "on_red"),
    "high": ("orange", "on_orange"),
    "medium": ("yellow", "on_yellow"),
    "low": ("blue", "on_blue"),
    "info": ("grey", "on_grey"),
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

UNICODE_GLYPHS = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "h": "─", "v": "│",
    "heavy": "━", "double": "═",
    "bar_full": "█", "bar_half": "▌",
    "ok": "✓", "fail": "✗", "warn": "!", "skip": "○",
    "arrow": "→", "bullet": "•", "dot": "·",
    "corner": "└", "tee": "├",
}

ASCII_GLYPHS = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "h": "-", "v": "|",
    "heavy": "=", "double": "=",
    "bar_full": "#", "bar_half": "=",
    "ok": "+", "fail": "x", "warn": "!", "skip": "o",
    "arrow": "->", "bullet": "*", "dot": ".",
    "corner": "`", "tee": "|",
}


def _stream_handles_unicode(stream) -> bool:
    """Whether this stream can encode the box-drawing set."""
    encoding = getattr(stream, "encoding", None) or ""
    if not encoding:
        return False
    try:
        "".join(UNICODE_GLYPHS.values()).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def enable_windows_vt() -> None:
    """Turn on virtual-terminal processing for a legacy Windows console.

    Windows Terminal and Git Bash already interpret escape sequences. A plain
    ``cmd.exe`` does not until asked, and without the ask it prints the codes
    literally, which is worse than having no colour at all.
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):  # stdout, stderr
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: BLE001 — cosmetic, never worth failing a scan
        pass


def supports_color(stream) -> bool:
    """Whether escape codes should be written to this particular stream.

    ``NO_COLOR`` is honoured because it is the cross-tool convention, and
    ``FORCE_COLOR`` because CI systems pipe output while still rendering it.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


def width(default: int = 100, maximum: int = 110, minimum: int = 60) -> int:
    """Usable columns, clamped.

    The maximum is not timidity: prose set across 200 columns is measurably
    harder to read than the same prose at 100, and a report is mostly prose.
    """
    try:
        columns = shutil.get_terminal_size(fallback=(default, 24)).columns
    except Exception:  # noqa: BLE001
        columns = default
    return max(minimum, min(maximum, columns - 2))


def visible_len(text: str) -> int:
    """Printable width, ignoring escape sequences."""
    return len(ANSI_RE.sub("", text))


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class Theme:
    """Colour and glyph decisions for one output stream.

    Bundled into an object so the renderer never asks "is colour on" again:
    it asks the theme for a styled string and gets the styled or plain one.
    """

    def __init__(self, stream=None, *, color: bool | None = None, ascii_only: bool | None = None):
        stream = stream if stream is not None else sys.stdout
        self.stream = stream
        self.color = supports_color(stream) if color is None else color
        if ascii_only is None:
            ascii_only = not _stream_handles_unicode(stream)
        self.glyphs = ASCII_GLYPHS if ascii_only else UNICODE_GLYPHS
        self.width = width()

    def s(self, text: str, *styles: str) -> str:
        """Style ``text``, or return it untouched when colour is off."""
        if not self.color or not styles:
            return text
        prefix = "".join(STYLES[name] for name in styles if name in STYLES)
        return f"{prefix}{text}{RESET}" if prefix else text

    def g(self, name: str) -> str:
        return self.glyphs.get(name, "")

    # ── composition ────────────────────────────────────────────────────────

    def rule(self, char: str = "h", *styles: str) -> str:
        return self.s(self.g(char) * self.width, *(styles or ("grey",)))

    def heading(self, text: str, *, style: str = "cyan") -> list[str]:
        return [
            self.s(self.g("double") * self.width, "grey"),
            "  " + self.s(text.upper(), "bold", style),
            self.s(self.g("double") * self.width, "grey"),
            "",
        ]

    def subheading(self, text: str, *styles: str) -> list[str]:
        line = f"{self.g('h') * 2} {text} "
        pad = max(0, self.width - visible_len(line))
        return [self.s(line, *styles) + self.s(self.g("h") * pad, "grey"), ""]

    def panel(self, title: str, rows: list[tuple[str, str]], *, style: str = "cyan") -> list[str]:
        """A titled box of label/value pairs.

        Values are never truncated. A box that hides the end of a hostname to
        preserve its own border has the priorities backwards.
        """
        label_w = max((len(label) for label, _ in rows), default=0)
        # Every line is exactly self.width columns: border, two spaces of
        # padding, the content, filler, border. Computed from the *visible*
        # length so a styled value does not push the right border out by the
        # length of its escape codes.
        content_w = self.width - 4
        top = f"{self.g('tl')}{self.g('h')} {title} "
        top += self.g("h") * max(0, self.width - visible_len(top) - 1) + self.g("tr")
        edge = self.s(self.g("v"), style)

        out = [self.s(top, style)]
        for label, value in rows:
            plain = f"{label.ljust(label_w)}   {strip_ansi(value)}"
            body = self.s(label.ljust(label_w), "grey") + "   " + value
            out.append(
                edge + "  " + body + " " * max(0, content_w - len(plain)) + edge
            )
        out.append(self.s(self.g("bl") + self.g("h") * (self.width - 2) + self.g("br"), style))
        out.append("")
        return out

    def severity_badge(self, severity: str) -> str:
        severity = severity.lower()
        _, bg = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
        if not self.color:
            return f"[{severity.upper():^8}]"
        return f"{STYLES[bg]}{STYLES['bold']}{STYLES['white']} {severity.upper():^6} {RESET}"

    def severity_color(self, severity: str) -> str:
        return SEVERITY_STYLE.get(severity.lower(), SEVERITY_STYLE["info"])[0]

    def bar(self, value: int, total: int, *, size: int = 28, style: str = "cyan") -> str:
        """A proportional bar. Any non-zero value gets at least one cell.

        Rounding a real finding down to an empty bar makes it look like zero,
        which is the one thing a severity chart must never do.
        """
        if total <= 0 or value <= 0:
            return ""
        filled = max(1, round(size * value / total))
        return self.s(self.g("bar_full") * filled, style)

    def wrap(self, text: str, indent: str = "", *, width_override: int | None = None) -> list[str]:
        """Wrap prose, preserving the paragraph breaks the source already has."""
        import textwrap

        limit = (width_override or self.width) - len(indent)
        out: list[str] = []
        for paragraph in str(text or "").split("\n"):
            paragraph = paragraph.rstrip()
            if not paragraph:
                out.append("")
                continue
            out.extend(
                textwrap.wrap(
                    paragraph, width=max(20, limit),
                    initial_indent=indent, subsequent_indent=indent,
                    break_long_words=False, break_on_hyphens=False,
                ) or [indent]
            )
        return out
