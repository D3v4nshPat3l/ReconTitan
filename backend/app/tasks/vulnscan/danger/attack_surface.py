"""Attack-surface inventory: crawl in-scope pages and classify every input point.

The inventory is the contract between recon and the bounded testing modules.
Each entry records where a probe may be sent, how, and with which parameters —
never the values a real user submitted.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup

from app.config import settings
from app.models.schemas import AttackSurfaceItem, InputPointType
from app.targeting import is_same_target_scope
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    ProbeResult,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)

logger = logging.getLogger("recontitan.danger.attack_surface")

MODULE = "attack_surface"

LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "logon", "account/login")
SEARCH_HINTS = ("search", "query", "q", "keyword", "find", "lookup", "s")
UPLOAD_HINTS = ("upload", "file", "attachment", "import", "avatar", "document")
API_HINTS = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/rpc/")

#: Query parameters that commonly reference a stored object (drives IDOR tests).
OBJECT_PARAM_RE = re.compile(
    r"^(?:id|uid|uuid|guid|user_?id|account_?id|file_?id|doc(?:ument)?_?id|order(?:_?id)?|"
    r"invoice|record|item_?id|profile_?id|customer_?id|ref|key|num(?:ber)?)$",
    re.IGNORECASE,
)
#: Query parameters that commonly accept a URL (drives SSRF tests).
URL_PARAM_RE = re.compile(
    r"^(?:url|uri|link|src|source|target|dest|destination|redirect|redirect_uri|next|"
    r"callback|webhook|image|image_?url|fetch|feed|proxy|load|domain|site|page_?url)$",
    re.IGNORECASE,
)
#: Path segments that look like an object reference (``/orders/1042``).
PATH_ID_RE = re.compile(
    r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)",
    re.IGNORECASE,
)

_SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".css", ".mp4", ".webm", ".webp", ".pdf", ".zip", ".gz",
)


def _in_scope(url: str, target: str) -> bool:
    host = urlsplit(url).hostname or ""
    return bool(host) and is_same_target_scope(host, target)


def _crawlable(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return not path.endswith(_SKIP_SUFFIXES)


def _classify_form(action: str, inputs: list[str], has_file: bool) -> InputPointType:
    haystack = f"{action} {' '.join(inputs)}".lower()
    if has_file or any(hint in haystack for hint in UPLOAD_HINTS):
        return InputPointType.UPLOAD_FORM
    if "password" in haystack or any(hint in haystack for hint in LOGIN_HINTS):
        return InputPointType.LOGIN_FORM
    if any(name.lower() in SEARCH_HINTS for name in inputs) or "search" in haystack:
        return InputPointType.SEARCH_FORM
    return InputPointType.GENERIC_FORM


def _classify_query(url: str, params: list[str]) -> InputPointType:
    lowered = url.lower()
    if any(hint in lowered for hint in API_HINTS):
        return InputPointType.API_ENDPOINT
    if any(URL_PARAM_RE.fullmatch(name) for name in params):
        return InputPointType.URL_PARAM
    if any(OBJECT_PARAM_RE.fullmatch(name) for name in params):
        return InputPointType.OBJECT_REFERENCE
    if any(name.lower() in SEARCH_HINTS for name in params):
        return InputPointType.SEARCH_FORM
    return InputPointType.QUERY_PARAM


def _item_id(method: str, url: str, params: list[str]) -> str:
    key = "|".join([method, url, ",".join(sorted(params))])
    return f"as_{fingerprint(key)[7:19]}"


def _extract_forms(page_url: str, soup: BeautifulSoup, target: str) -> list[AttackSurfaceItem]:
    items: list[AttackSurfaceItem] = []
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        if not _in_scope(action, target):
            continue
        method = str(form.get("method") or "GET").upper()
        if method not in {"GET", "POST"}:
            method = "GET"
        names: list[str] = []
        has_file = False
        for field in form.find_all(["input", "textarea", "select"]):
            field_type = str(field.get("type") or "").lower()
            if field_type == "file":
                has_file = True
            name = field.get("name")
            if name and str(name)[:100] not in names:
                names.append(str(name)[:100])
        if not names:
            continue
        enctype = str(form.get("enctype") or "").lower() or (
            "application/x-www-form-urlencoded" if method == "POST" else None
        )
        items.append(AttackSurfaceItem(
            id=_item_id(method, action, names),
            url=action[:2000],
            method=method,
            input_type=_classify_form(action, names, has_file),
            parameters=names[:100],
            content_type=enctype,
            source="form",
        ))
    return items


def _extract_links(page_url: str, soup: BeautifulSoup, target: str) -> tuple[list[str], list[AttackSurfaceItem]]:
    links: list[str] = []
    items: list[AttackSurfaceItem] = []
    for anchor in soup.find_all("a", href=True):
        url = urljoin(page_url, str(anchor["href"]).strip())
        if not url.startswith(("http://", "https://")) or not _in_scope(url, target):
            continue
        split = urlsplit(url)
        clean = url.split("#", 1)[0]
        if clean not in links and _crawlable(clean):
            links.append(clean)
        params = [name[:100] for name, _ in parse_qsl(split.query, keep_blank_values=True)]
        if params:
            items.append(AttackSurfaceItem(
                id=_item_id("GET", clean, params),
                url=clean[:2000],
                method="GET",
                input_type=_classify_query(clean, params),
                parameters=params[:100],
                source="link",
            ))
        elif PATH_ID_RE.search(split.path):
            items.append(AttackSurfaceItem(
                id=_item_id("GET", clean, []),
                url=clean[:2000],
                method="GET",
                input_type=InputPointType.OBJECT_REFERENCE,
                parameters=[],
                source="path",
            ))
    return links, items


def _dedupe(items: list[AttackSurfaceItem]) -> list[AttackSurfaceItem]:
    seen: dict[str, AttackSurfaceItem] = {}
    for item in items:
        seen.setdefault(item.id, item)
    return list(seen.values())


def build_attack_surface(
    target: str,
    budget: DangerBudget,
    *,
    seeds: list[str] | None = None,
) -> tuple[list[AttackSurfaceItem], list[str]]:
    """Crawl bounded in-scope pages and return the classified input inventory.

    Returns ``(items, visited_urls)``. Crawling stops at
    ``DANGER_MAX_CRAWL_PAGES`` pages or when the request budget runs out.
    """
    queue: list[str] = []
    for seed in seeds or []:
        for scheme in ("https", "http"):
            candidate = seed if seed.startswith("http") else f"{scheme}://{seed}/"
            if candidate not in queue:
                queue.append(candidate)
            if seed.startswith("http"):
                break
    if not queue:
        queue = [f"https://{target}/", f"http://{target}/"]

    visited: list[str] = []
    items: list[AttackSurfaceItem] = []
    seen_urls: set[str] = set()

    while queue and len(visited) < settings.DANGER_MAX_CRAWL_PAGES:
        url = queue.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        result = budget.probe(MODULE, "GET", url, counts_as_payload=False)
        if not result.ok or result.response is None:
            continue
        content_type = result.response.headers.get("Content-Type", "").lower()
        visited.append(result.response.url)
        if "html" not in content_type:
            continue
        soup = BeautifulSoup(result.text, "html.parser")
        items.extend(_extract_forms(result.response.url, soup, target))
        links, link_items = _extract_links(result.response.url, soup, target)
        items.extend(link_items)
        for link in links:
            if link not in seen_urls and len(queue) < settings.DANGER_MAX_CRAWL_PAGES * 3:
                queue.append(link)

    return _dedupe(items)[: settings.DANGER_MAX_ENDPOINTS * 4], visited


def _type_counts(items: list[AttackSurfaceItem]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.input_type.value] = counts.get(item.input_type.value, 0) + 1
    return counts


def run_attack_surface(
    target: str,
    budget: DangerBudget,
    *,
    seeds: list[str] | None = None,
) -> tuple[list[AttackSurfaceItem], list[dict]]:
    """Produce the attack-surface inventory plus its reporting findings."""
    items, visited = build_attack_surface(target, budget, seeds=seeds)
    counts = _type_counts(items)
    findings: list[dict] = []

    inventory_lines = []
    for item in items[:80]:
        params = ", ".join(item.parameters[:12]) or "(none)"
        inventory_lines.append(f"{item.method} {truncated(item.url, 140)} [{item.input_type.value}] params={params}")

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_attack_surface",
        severity="info",
        title=f"Attack Surface Inventory - {len(items)} input point(s)",
        description=(
            f"Danger Mode crawled {len(visited)} in-scope page(s) for {target} and classified every discovered "
            "form, search field, query parameter, API endpoint, upload, and object reference. The inventory drives "
            "which bounded probes each testing module is allowed to send."
        ),
        evidence=evidence_block([
            ("Pages crawled", len(visited)),
            ("Input points", len(items)),
            *[(f"Type {name}", value) for name, value in sorted(counts.items())],
            ("Inventory", "\n" + "\n".join(inventory_lines) if inventory_lines else "No input points discovered"),
        ]),
        remediation=(
            "Review each exposed input point for authentication, authorization, input validation, and output "
            "encoding. Remove unused parameters and endpoints from the public surface."
        ),
        asset=target,
    ))

    upload_forms = [item for item in items if item.input_type == InputPointType.UPLOAD_FORM]
    if upload_forms:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_dangerous_feature",
            severity="medium",
            title=f"File Upload Endpoints Exposed - {len(upload_forms)}",
            description=(
                "File-upload input points were discovered. Danger Mode does not upload files. Upload handlers that "
                "accept unvalidated file types, names, or content are a common path to stored payloads and command "
                "injection through filename handling."
            ),
            evidence=evidence_block([
                (f"Upload {index}", f"{item.method} {truncated(item.url, 160)} params={', '.join(item.parameters[:8])}")
                for index, item in enumerate(upload_forms[:20], 1)
            ]),
            remediation=(
                "Validate file type by content rather than extension, generate server-side filenames, store uploads "
                "outside the web root, and scan content before it is served back."
            ),
            owasp="A04:2021-Insecure Design",
            attack_vector="Unvalidated file upload",
            asset=target,
        ))

    logger.info("[danger:attack_surface] %d input points from %d pages", len(items), len(visited))
    return items, findings


def baseline_probe(budget: DangerBudget, item: AttackSurfaceItem, module: str) -> ProbeResult:
    """Fetch an unmodified copy of an endpoint so probes can be compared to it."""
    return budget.probe(module, "GET", item.url, counts_as_payload=False)
