"""
Vuln Scan Phase — Nuclei, Nikto, ffuf/Gobuster, SQLMap, testssl subprocess wrappers.
Also includes NVD CVE API lookup for technology-based CVE matching.
"""
import subprocess, shutil, requests, logging, json, tempfile, os, re
logger = logging.getLogger("recontitan.vulnscan")
TIMEOUT_NUCLEI = int(os.getenv("SCAN_TIMEOUT_NUCLEI", "600"))
TIMEOUT_DEFAULT = int(os.getenv("SCAN_TIMEOUT_DEFAULT", "120"))


def _run(cmd, timeout=120):
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        logger.warning("[vulnscan] %s: %s", cmd[0], e)
        return ""


def run_nuclei(target: str) -> list[dict]:
    """Nuclei template-based vulnerability scanner."""
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    if not shutil.which("nuclei"):
        return [{"tool":"nuclei","category":"vuln_scan","severity":"info",
                 "title":"Nuclei Not Installed",
                 "description":"Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                 "evidence":"Binary 'nuclei' not found."}]
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
        outfile = f.name
    _run(["nuclei","-u",url,"-json-export",outfile,
          "-severity","low,medium,high,critical","-silent"],TIMEOUT_NUCLEI)
    try:
        with open(outfile) as f:
            for line in f:
                try:
                    item = json.loads(line.strip())
                    sev  = item.get("info",{}).get("severity","info")
                    name = item.get("info",{}).get("name","Unknown")
                    desc = item.get("info",{}).get("description","")
                    cve  = item.get("info",{}).get("classification",{}).get("cve-id",[""])
                    cvss = item.get("info",{}).get("classification",{}).get("cvss-score",None)
                    matched = item.get("matched-at","")
                    remediation = item.get("info",{}).get("remediation","")
                    findings.append({
                        "tool":"nuclei","category":"vulnerability","severity":sev,
                        "title":f"[Nuclei] {name}",
                        "description":desc,
                        "evidence":f"Matched at: {matched}",
                        "cve_id":cve[0] if cve else None,
                        "cvss_score":cvss,
                        "remediation":remediation or None,
                    })
                except Exception:
                    pass
        os.unlink(outfile)
    except Exception as e:
        logger.warning("[nuclei] Output parse error: %s", e)
    logger.info("[nuclei] %d findings for %s", len(findings), target)
    return findings


def run_nikto(target: str) -> list[dict]:
    """Nikto web server scanner."""
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    if not shutil.which("nikto"):
        return [{"tool":"nikto","category":"vuln_scan","severity":"info",
                 "title":"Nikto Not Installed",
                 "description":"Install: https://github.com/sullo/nikto","evidence":""}]
    raw = _run(["nikto","-h",url,"-nointeractive","-maxtime","5m"], 360)
    issues = [l.strip() for l in raw.splitlines() if l.strip().startswith("+")]
    if issues:
        findings.append({
            "tool":"nikto","category":"web_server_scan","severity":"medium",
            "title":f"Nikto — {len(issues)} Issues Found",
            "description":f"Nikto found {len(issues)} issues on {url}.",
            "evidence":"\n".join(issues[:40]),
        })
    return findings


def run_dir_fuzzing(target: str) -> list[dict]:
    """Directory fuzzing via ffuf or gobuster."""
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = None

    # Try ffuf
    if shutil.which("ffuf") and wordlist:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            outfile = f.name
        _run(["ffuf","-u",f"{url}/FUZZ","-w",wordlist,
              "-mc","200,301,302,403","-o",outfile,"-of","json","-t","50"],
             TIMEOUT_DEFAULT)
        try:
            with open(outfile) as f:
                data = json.load(f)
                results = data.get("results",[])
                found = [f"{r['url']} [{r['status']}]" for r in results]
                if found:
                    findings.append({
                        "tool":"ffuf","category":"directory_fuzzing","severity":"medium",
                        "title":f"ffuf — {len(found)} Hidden Paths Found",
                        "description":f"Directory/file fuzzing found {len(found)} accessible paths.",
                        "evidence":"\n".join(f"• {r}" for r in found[:50]),
                        "remediation":"Review found paths. Restrict access to sensitive endpoints.",
                    })
            os.unlink(outfile)
        except Exception:
            pass
        return findings

    # Try gobuster
    if shutil.which("gobuster") and wordlist:
        raw = _run(["gobuster","dir","-u",url,"-w",wordlist,"-q","--no-error"],TIMEOUT_DEFAULT)
        found = [l.strip() for l in raw.splitlines() if l.strip().startswith("/")]
        if found:
            findings.append({
                "tool":"gobuster","category":"directory_fuzzing","severity":"medium",
                "title":f"Gobuster — {len(found)} Paths Found",
                "description":f"Directory enumeration found {len(found)} paths.",
                "evidence":"\n".join(f"• {p}" for p in found[:50]),
            })
        return findings

    # Fallback: no tool available
    findings.append({
        "tool":"dir_fuzzing","category":"directory_fuzzing","severity":"info",
        "title":"Directory Fuzzing Skipped — No Tool Available",
        "description":"ffuf or gobuster not installed. Install for directory brute-forcing.",
        "evidence":"Install ffuf: https://github.com/ffuf/ffuf",
    })
    return findings


def run_sqlmap_check(target: str) -> list[dict]:
    """Basic SQLMap injection test (GET parameter check only)."""
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    if not shutil.which("sqlmap"):
        return [{"tool":"sqlmap","category":"injection","severity":"info",
                 "title":"SQLMap Not Installed",
                 "description":"Install: pip install sqlmap or https://github.com/sqlmapproject/sqlmap",
                 "evidence":""}]
    # A private directory per run: a fixed path under /tmp is world-writable,
    # predictable enough to pre-create as a symlink, and shared by concurrent
    # scans that would then overwrite each other's output.
    output_dir = tempfile.mkdtemp(prefix="sqlmap_rt_")
    try:
        raw = _run(["sqlmap","-u",f"{url}/?id=1","--batch","--level=1",
                    "--risk=1","--forms","--crawl=1","--output-dir",output_dir],
                   TIMEOUT_DEFAULT)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
    if "is vulnerable" in raw.lower() or "sql injection" in raw.lower():
        findings.append({
            "tool":"sqlmap","category":"injection","severity":"critical",
            "title":"SQL Injection Detected",
            "description":"SQLMap detected SQL injection vulnerability.",
            "evidence":raw[:1000],
            "remediation":"Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        })
    else:
        findings.append({
            "tool":"sqlmap","category":"injection","severity":"info",
            "title":"SQLMap — No Basic Injection Detected",
            "description":"Basic SQLMap scan found no obvious SQL injection on entry points.",
            "evidence":"No 'is vulnerable' in SQLMap output.",
        })
    return findings


def extract_cvss(metrics: dict) -> tuple[float, str, str]:
    """Return (score, vector, severity) preferring CVSS v3.1, then v3.0, then v2.

    The previous chain defaulted each lookup to ``[{}]``, which is a non-empty
    list and therefore truthy, so the ``or`` stopped at the first branch and
    v3.0/v2 were never consulted. Every CVE without v3.1 data scored 0.0 and
    was reported as "low" -- including genuinely high-severity older CVEs.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            score = float(score)
            severity = (
                "critical" if score >= 9 else
                "high" if score >= 7 else
                "medium" if score >= 4 else
                "low" if score > 0 else "info"
            )
            return score, str(data.get("vectorString", "")), severity
    return 0.0, "", "info"


def run_nvd_cve_lookup(tech_name: str, version: str = "") -> list[dict]:
    """Query NVD API for CVEs matching a technology name/version. Free, no key needed."""
    findings = []
    query = f"{tech_name} {version}".strip()
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 10},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("vulnerabilities", [])
        for item in items:
            cve  = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d["lang"] == "en"), "")
            score, _vector, sev = extract_cvss(cve.get("metrics", {}))
            findings.append({
                "tool":"nvd_cve","category":"cve_finding","severity":sev,
                "title":f"Potential CVE Match: {cve_id} (CVSS {score}) — {tech_name}",
                "description":(desc[:360] + " Keyword matches require manual product/version validation before remediation."),
                "evidence":f"NVD CVE-ID: {cve_id}\nCVSS Score: {score}\nQuery: {query}",
                "cve_id":cve_id,"cvss_score":score,
                "remediation":f"Check {cve_id} on https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
    except Exception as e:
        logger.warning("[nvd_cve] Error for '%s': %s", query, e)
    return findings
