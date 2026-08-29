"""
ReconTitan — News Router (Live RSS Feed)

Fetches REAL latest cybersecurity news from multiple RSS sources.
Results are cached for 15 minutes to avoid hammering RSS feeds.
Each item includes the direct URL to the original article.
"""

from fastapi import APIRouter
from datetime import datetime, timezone, timedelta
try:
    import feedparser
except ImportError:  # Optional in minimal/test environments
    feedparser = None
import logging
import asyncio
import httpx
import hashlib
import time
import re
from email.utils import parsedate_to_datetime

logger = logging.getLogger("recontitan.news")
router = APIRouter(prefix="/api", tags=["news"])

# ─── RSS Feed Sources ───────────────────────────────────────
RSS_SOURCES = [
    {
        "key":  "thehackernews",
        "name": "THE HACKER NEWS",
        "url":  "https://feeds.feedburner.com/TheHackersNews",
        "cat":  "threats",
    },
    {
        "key":  "bleeping",
        "name": "BLEEPINGCOMPUTER",
        "url":  "https://www.bleepingcomputer.com/feed/",
        "cat":  "malware",
    },
    {
        "key":  "krebs",
        "name": "KREBS ON SECURITY",
        "url":  "https://krebsonsecurity.com/feed/",
        "cat":  "breaches",
    },
    {
        "key":  "darkreading",
        "name": "DARK READING",
        "url":  "https://www.darkreading.com/rss.xml",
        "cat":  "vulns",
    },
    {
        "key":  "threatpost",
        "name": "THREATPOST",
        "url":  "https://threatpost.com/feed/",
        "cat":  "vulns",
    },
    {
        "key":  "securityweek",
        "name": "SECURITY WEEK",
        "url":  "https://feeds.feedburner.com/securityweek",
        "cat":  "threats",
    },
    {
        "key":  "cisa",
        "name": "CISA ADVISORIES",
        "url":  "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "cat":  "vulns",
    },
    {
        "key":  "nvd",
        "name": "NVD CVE FEED",
        "url":  "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "cat":  "vulns",
    },
]

# ─── Category classifier keywords ──────────────────────────
_CAT_RULES = {
    "malware":  ["malware", "ransomware", "trojan", "botnet", "worm", "stealer",
                 "backdoor", "rootkit", "cryptominer", "apt", "lockbit", "infostealer"],
    "breaches": ["breach", "leak", "exposed", "stolen", "data dump", "records",
                 "compromised", "exfiltrat", "database"],
    "vulns":    ["cve-", "zero-day", "rce", "vulnerability", "patch", "exploit",
                 "critical", "advisory", "disclosure", "nuclei"],
    "osint":    ["osint", "geolocation", "satellite", "open source intel",
                 "tracking", "surveillance", "investigation"],
    "threats":  ["apt", "threat actor", "nation-state", "phishing", "campaign",
                 "attack", "hacker", "cybercrime", "espionage"],
}

def _classify(title: str, summary: str, default_cat: str) -> str:
    text = (title + " " + summary).lower()
    for cat, keywords in _CAT_RULES.items():
        if any(kw in text for kw in keywords):
            return cat
    return default_cat

def _severity(title: str, summary: str) -> str:
    text = (title + " " + summary).lower()
    if any(w in text for w in ["zero-day", "critical", "rce", "actively exploited",
                                "emergency", "lockbit", "ransomware", "nation-state"]):
        return "critical"
    if any(w in text for w in ["high", "breach", "stolen", "apt", "backdoor",
                                "privilege escalation", "authentication bypass"]):
        return "high"
    if any(w in text for w in ["medium", "phishing", "vulnerability", "exposed",
                                "misconfiguration"]):
        return "medium"
    if any(w in text for w in ["patch", "update", "advisory", "low"]):
        return "low"
    return "info"

def _extract_tags(title: str) -> list[str]:
    """Pull CVE IDs, product names, and key terms as tags."""
    tags = []
    # CVE IDs
    cves = re.findall(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
    tags.extend([c.upper() for c in cves[:2]])
    # Capitalised words that look like product/org names
    words = re.findall(r"\b[A-Z][A-Z0-9\-]{2,}\b", title)
    for w in words:
        if w not in {"THE", "AND", "FOR", "THIS", "NEW", "CVE", "HOW", "WHY",
                     "FROM", "WITH", "THAT", "ARE", "WAS", "HAS"}:
            tags.append(w)
    return list(dict.fromkeys(tags))[:4]  # unique, max 4

def _relative_time(dt: datetime) -> str:
    """Convert datetime to '2h ago' style string."""
    if not dt:
        return "recently"
    now = datetime.now(timezone.utc)
    diff = now - dt.astimezone(timezone.utc)
    secs = int(diff.total_seconds())
    if secs < 60:       return "just now"
    if secs < 3600:     return f"{secs // 60}m ago"
    if secs < 86400:    return f"{secs // 3600}h ago"
    if secs < 604800:   return f"{secs // 86400}d ago"
    return dt.strftime("%b %d")

def _clean_summary(raw: str) -> str:
    """Strip HTML tags and truncate."""
    clean = re.sub(r"<[^>]+>", "", raw or "")
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:280] + ("…" if len(clean) > 280 else "")

def _parse_date(entry) -> datetime | None:
    """Try multiple feedparser date fields."""
    for field in ("published_parsed", "updated_parsed", "created_parsed"):
        t = getattr(entry, field, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=timezone.utc)
            except Exception:
                pass
    # Try string fields
    for field in ("published", "updated"):
        s = getattr(entry, field, None)
        if s:
            try:
                return parsedate_to_datetime(s)
            except Exception:
                pass
    return None


# ─── Cache ──────────────────────────────────────────────────
_cache: dict = {"items": [], "expires": 0}
_CACHE_TTL = 15 * 60  # 15 minutes


async def _fetch_one(client: httpx.AsyncClient, source: dict) -> list[dict]:
    """Fetch and parse one RSS feed asynchronously."""
    items = []
    if feedparser is None:
        logger.warning("feedparser is not installed; news feed is unavailable")
        return items
    try:
        resp = await client.get(source["url"], timeout=8.0)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:8]:  # top 8 per source
            title   = (entry.get("title") or "").strip()
            if not title:
                continue
            summary  = _clean_summary(entry.get("summary") or entry.get("description") or "")
            link     = entry.get("link") or entry.get("id") or ""
            pub_date = _parse_date(entry)

            # Skip anything older than 7 days
            if pub_date:
                age = datetime.now(timezone.utc) - pub_date.astimezone(timezone.utc)
                if age.days > 7:
                    continue

            cat = _classify(title, summary, source["cat"])
            sev = _severity(title, summary)
            tags = _extract_tags(title)
            # A stable id for de-duplicating feed items across refreshes.
            # Nothing authenticates on it, so collision resistance is not a
            # security property here -- usedforsecurity=False says exactly that.
            uid  = hashlib.md5(  # noqa: S324
                (title + link).encode(), usedforsecurity=False
            ).hexdigest()[:12]

            items.append({
                "id":           uid,
                "title":        title,
                "summary":      summary,
                "url":          link,
                "source":       source["name"],
                "source_key":   source["key"],
                "severity":     sev,
                "tags":         tags,
                "category":     cat,
                "published_at": _relative_time(pub_date),
                "published_ts": pub_date.isoformat() if pub_date else None,
            })
    except Exception as e:
        logger.warning("RSS fetch failed for %s: %s", source["key"], str(e)[:100])
    return items


async def _fetch_all_feeds() -> list[dict]:
    """Fetch all RSS feeds concurrently, return sorted by recency."""
    async with httpx.AsyncClient(
        headers={"User-Agent": "ReconTitan-NewsFeed/1.0"},
        follow_redirects=True,
    ) as client:
        tasks = [_fetch_one(client, src) for src in RSS_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_items = []
    for r in results:
        if isinstance(r, list):
            all_items.extend(r)

    # Sort: items with a timestamp first (newest), then the rest
    def sort_key(item):
        ts = item.get("published_ts")
        if ts:
            try:
                return datetime.fromisoformat(ts)
            except Exception:
                pass
        return datetime.min.replace(tzinfo=timezone.utc)

    all_items.sort(key=sort_key, reverse=True)
    return all_items


async def _get_cached_news() -> list[dict]:
    """Return cached items, refreshing if stale."""
    now = time.time()
    if _cache["items"] and _cache["expires"] > now:
        return _cache["items"]

    logger.info("Refreshing cybersecurity news from RSS feeds...")
    items = await _fetch_all_feeds()

    if items:
        _cache["items"]   = items
        _cache["expires"] = now + _CACHE_TTL
        logger.info("Fetched %d news items from RSS feeds", len(items))
    else:
        # If all feeds fail, keep old cache a bit longer
        logger.warning("All RSS feeds failed — serving stale cache")
        _cache["expires"] = now + 120  # retry in 2 min

    return _cache["items"]


# ─── API Endpoints ──────────────────────────────────────────

@router.get("/news")
async def get_news(category: str = "all", limit: int = 30):
    """
    Live cybersecurity news from RSS feeds.
    Cached for 15 minutes. Each item includes the original article URL.
    """
    items = await _get_cached_news()

    if category != "all":
        items = [n for n in items if n.get("category") == category]

    return {
        "news": items[:limit],
        "total": len(items),
        "cached": _cache["expires"] > time.time(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/news/refresh")
async def refresh_news():
    """Force-refresh the news cache (bypasses TTL)."""
    _cache["expires"] = 0  # invalidate
    items = await _get_cached_news()
    return {"status": "refreshed", "total": len(items)}
