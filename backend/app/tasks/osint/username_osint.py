"""Sherlock, theHarvester, Maigret subprocess wrappers."""
import subprocess, shutil, logging, json, tempfile, os
logger = logging.getLogger("recontitan.osint.username_osint")

def _run(cmd, timeout=120):
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        logger.warning("[username_osint] %s: %s", cmd[0], e)
        return ""

def run_sherlock(username: str) -> list[dict]:
    if not shutil.which("sherlock"):
        return [{"tool":"sherlock","category":"username_osint","severity":"info",
                 "title":"Sherlock Not Installed",
                 "description":"Install: pip install sherlock-project","evidence":""}]
    raw = _run(["sherlock", username, "--print-found", "--timeout","10"], 180)
    found = [l.strip() for l in raw.splitlines() if l.strip().startswith("[+]")]
    return [{"tool":"sherlock","category":"username_osint","severity":"info",
             "title":f"Sherlock — '{username}' found on {len(found)} platforms",
             "description":f"Username '{username}' active on {len(found)} websites.",
             "evidence":"\n".join(found[:60])}] if found else []

def run_theharvester(target: str) -> list[dict]:
    domain = target.replace("https://","").replace("http://","").split("/")[0]
    binary = next((b for b in ["theHarvester","theharvester"] if shutil.which(b)), None)
    if not binary:
        return [{"tool":"theHarvester","category":"osint_aggregator","severity":"info",
                 "title":"theHarvester Not Installed","description":"pip install theHarvester","evidence":""}]
    raw = _run([binary,"-d",domain,"-b","bing,google,crtsh"],120)
    emails = list({l.strip() for l in raw.splitlines() if "@" in l and domain.split(".")[0] in l})
    hosts  = list({l.strip() for l in raw.splitlines() if "." in l and domain in l and "@" not in l})
    findings = []
    if emails or hosts:
        findings.append({"tool":"theHarvester","category":"osint_aggregator","severity":"info",
                         "title":f"theHarvester — {len(emails)} emails, {len(hosts)} hosts",
                         "description":f"OSINT harvest for {domain}.",
                         "evidence":"\n".join(f"• {e}" for e in emails[:20])})
    if emails:
        findings.append({"tool":"theHarvester","category":"email_exposure","severity":"medium",
                         "title":f"{len(emails)} Employee Emails Exposed",
                         "description":"Exposed emails are phishing/credential stuffing targets.",
                         "evidence":"\n".join(f"• {e}" for e in emails[:30]),
                         "remediation":"Enable MFA. Monitor breaches via HaveIBeenPwned."})
    return findings

def run_maigret(username: str) -> list[dict]:
    if not shutil.which("maigret"):
        return [{"tool":"maigret","category":"username_osint","severity":"info",
                 "title":"Maigret Not Installed","description":"pip install maigret","evidence":""}]
    raw = _run(["maigret", username, "--no-progressbar"], 180)
    found = [l for l in raw.splitlines() if "[+]" in l]
    return [{"tool":"maigret","category":"username_osint","severity":"info",
             "title":f"Maigret — '{username}' on {len(found)} sites",
             "description":f"Maigret searched 3000+ sites for '{username}'.",
             "evidence":"\n".join(found[:50])}]
