"""robots.txt and sitemap.xml analysis for the OSINT phase."""
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.osint.robots_sitemap")
TIMEOUT = 12

SENSITIVE_PATHS = [
    "admin", "administrator", "manage", "management", "dashboard",
    "login", "signin", "auth", "portal", "panel",
    "backup", "bak", "old", "archive", "tmp", "temp",
    "config", "configuration", "settings",
    "api", "graphql", "swagger", "api-docs",
    "phpmyadmin", "dbadmin", "mysql",
    ".git", ".env", ".htaccess",
    "wp-admin", "wp-login", "xmlrpc",
    "install", "setup", "debug",
    "upload", "uploads", "files",
    "secret", "private", "internal",
    "test", "staging", "dev",
    "phpinfo", "info.php",
]

def run_robots_sitemap(target: str) -> list[dict]:
    """Fetch and analyze robots.txt and sitemap.xml."""
    domain = normalize_target(target)
    base_url = f"https://{domain}/"
    findings = []

    # ── robots.txt ──
    try:
        robots_url  = urljoin(base_url, "/robots.txt")
        resp = safe_get(robots_url, timeout=TIMEOUT, max_bytes=256 * 1024)

        if resp.status_code == 200 and "text" in resp.headers.get("Content-Type", ""):
            lines = resp.text.strip().split("\n")
            disallow_paths = []
            allow_paths    = []
            sitemaps       = []

            for line in lines:
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallow_paths.append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allow_paths.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemaps.append(line.split(":", 1)[1].strip())

            # Find sensitive disallowed paths
            sensitive = [p for p in disallow_paths
                         if any(kw in p.lower() for kw in SENSITIVE_PATHS)]

            evidence = f"URL: {robots_url}\n\n"
            evidence += f"Disallow entries ({len(disallow_paths)}):\n"
            evidence += "\n".join(f"  Disallow: {p}" for p in disallow_paths[:50])
            if sitemaps:
                evidence += f"\n\nSitemap references:\n" + "\n".join(f"  {s}" for s in sitemaps)

            sev = "medium" if sensitive else "info"
            findings.append({
                "tool":        "robots_txt",
                "category":    "robots_txt",
                "severity":    sev,
                "title":       f"robots.txt Analyzed — {len(disallow_paths)} Disallow entries",
                "description": (
                    f"The robots.txt file for {domain} reveals {len(disallow_paths)} disallowed paths. "
                    "Disallow entries tell search engines what NOT to index — but attackers read these "
                    "to find hidden admin panels and sensitive directories."
                ),
                "evidence":    evidence,
            })

            if sensitive:
                findings.append({
                    "tool":        "robots_txt",
                    "category":    "sensitive_paths_disclosed",
                    "severity":    "medium",
                    "title":       f"Sensitive Paths Revealed in robots.txt — {len(sensitive)} found",
                    "description": (
                        f"{len(sensitive)} sensitive paths are listed in robots.txt. "
                        "These paths may expose admin panels, backups, or internal tools."
                    ),
                    "evidence":    "\n".join(f"• {p}" for p in sensitive),
                    "remediation": (
                        "Remove sensitive paths from robots.txt. Use authentication/firewall rules "
                        "instead of relying on robots.txt for security."
                    ),
                })
        else:
            logger.debug("[robots] Not found or non-text for %s", domain)

    except Exception as e:
        logger.warning("[robots] Error for %s: %s", domain, e)

    # ── sitemap.xml ──
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        resp = safe_get(sitemap_url, timeout=TIMEOUT, max_bytes=1024 * 1024)

        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "xml")
            urls = [loc.text.strip() for loc in soup.find_all("loc")]

            # Find interesting paths in sitemap
            interesting = [u for u in urls
                           if any(kw in u.lower() for kw in SENSITIVE_PATHS)]

            if urls:
                evidence = f"URL: {sitemap_url}\nTotal URLs indexed: {len(urls)}\n\n"
                evidence += "Sample URLs:\n" + "\n".join(f"  • {u}" for u in urls[:30])

                findings.append({
                    "tool":        "sitemap_xml",
                    "category":    "sitemap",
                    "severity":    "info",
                    "title":       f"sitemap.xml — {len(urls)} URLs Indexed",
                    "description": (
                        f"The sitemap.xml for {domain} lists {len(urls)} pages. "
                        "This reveals the site structure and all publicly declared pages."
                    ),
                    "evidence":    evidence,
                })

                if interesting:
                    findings.append({
                        "tool":        "sitemap_xml",
                        "category":    "sensitive_paths_disclosed",
                        "severity":    "low",
                        "title":       f"Sensitive Paths in sitemap.xml — {len(interesting)} found",
                        "description": "Sitemap.xml contains entries pointing to sensitive-looking paths.",
                        "evidence":    "\n".join(f"• {u}" for u in interesting[:20]),
                    })

    except Exception as e:
        logger.debug("[sitemap] Error for %s: %s", domain, e)

    logger.info("[robots_sitemap] %d findings for %s", len(findings), domain)
    return findings
