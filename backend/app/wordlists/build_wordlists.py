"""Generate the bundled directory-enumeration wordlists.

The lists are generated rather than hand-maintained so that the composition
rules are visible and reviewable: what goes in, why, and in which tier. A flat
checked-in text file answers none of those questions, and a wordlist nobody can
reason about is a wordlist nobody can trim.

Run it from the repository root when the source lists below change:

    python backend/app/wordlists/build_wordlists.py

Three tiers, because the right size depends on what the scan is for:

* ``small``   -- the highest-signal paths. Seconds, not minutes.
* ``common``  -- the default. Broad enough for a real assessment.
* ``big``     -- adds systematic variations, numbered and dated names.
"""

from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent

# Administrative and authentication surfaces. Highest signal in the set: a
# reachable one of these is immediately worth investigating.
ADMIN = """
admin administrator admin1 admin2 adminpanel admin-panel admin_panel
adminarea admin-area administration adminlogin admin-login admin_login
admincp admin-cp cp control controlpanel control-panel dashboard
manage manager management moderator webadmin wp-admin sysadmin
backend backoffice back-office console panel siteadmin useradmin
login logon signin sign-in signup sign-up register registration
auth authenticate authentication oauth oauth2 sso saml openid
logout signout password passwd forgot forgot-password reset
reset-password recover recovery account accounts profile user users
member members myaccount my-account session sessions token
""".split()

# Application and API structure. These map the app rather than expose it.
APPLICATION = """
api api1 api2 apis rest restapi graphql graphiql gql rpc jsonrpc soap
v1 v2 v3 v4 api/v1 api/v2 api/v3 public private internal external
app apps application web www site main home index default start
static assets asset media files file upload uploads download downloads
img images image css js javascript scripts script styles stylesheets
fonts vendor vendors node_modules bower_components dist build out
docs doc documentation swagger swagger-ui api-docs openapi redoc
help support faq about contact search sitemap feed rss atom
blog news press events forum forums community wiki portal shop store
cart checkout order orders payment payments invoice invoices billing
""".split()

# Configuration, source control and deployment leftovers. A reachable one of
# these is usually a real finding rather than a lead.
EXPOSURE = """
config configuration configs settings setting conf .env .env.local
.env.production .env.backup env environment .git .git/config .git/HEAD
.svn .hg .bzr .gitignore .gitlab-ci.yml .travis.yml Dockerfile
docker-compose.yml composer.json composer.lock package.json
package-lock.json yarn.lock Gemfile Gemfile.lock requirements.txt
web.config app.config appsettings.json wp-config.php config.php
configuration.php settings.php database.yml secrets.yml credentials
backup backups bak old new temp tmp test tests testing demo sample
samples example examples staging stage dev development prod production
archive archives dump dumps export exports import imports data db
database sql mysql postgres mongo redis logs log error errors debug
trace info status health healthz ready readiness live liveness metrics
actuator actuator/health actuator/env server-status server-info
phpinfo phpinfo.php info.php test.php phpmyadmin pma adminer
""".split()

# Files that are commonly reachable and commonly forgotten.
FILES = """
robots.txt sitemap.xml sitemap_index.xml humans.txt security.txt
.well-known/security.txt .well-known/change-password crossdomain.xml
clientaccesspolicy.xml favicon.ico manifest.json service-worker.js
sw.js browserconfig.xml ads.txt app-ads.txt readme readme.txt
README.md CHANGELOG.md LICENSE INSTALL UPGRADE TODO todo.txt
index.html index.php index.jsp index.asp index.aspx default.html
home.html main.html error.html 404.html 500.html maintenance.html
.htaccess .htpasswd .DS_Store Thumbs.db web.xml crossdomain
""".split()

# Platform and framework conventions. Cheap to test, and each one identifies
# the stack when it answers.
PLATFORM = """
wp-content wp-includes wp-json wp-login.php xmlrpc.php wordpress
drupal joomla magento typo3 umbraco sitecore craft laravel symfony
django flask rails spring struts tomcat jenkins gitlab jira
confluence grafana kibana prometheus elasticsearch solr rabbitmq
nagios zabbix cacti webmin cpanel plesk whm directadmin
owa exchange autodiscover activesync ews rdweb citrix vpn
portainer rancher kubernetes k8s consul vault nomad traefik
""".split()

#: Only the tiers above this size get the systematic variations.
NUMERIC_BASES = ("backup", "admin", "test", "old", "api", "db", "dump", "site", "web")
YEARS = tuple(str(year) for year in range(2018, 2028))


def _normalise(entries) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for entry in entries:
        entry = entry.strip().strip("/")
        if not entry or entry.startswith("#"):
            continue
        if entry in seen:
            continue
        seen.add(entry)
        out.append(entry)
    return out


def build() -> dict[str, list[str]]:
    small = _normalise(ADMIN[:60] + EXPOSURE[:60] + FILES[:30])
    common = _normalise(ADMIN + APPLICATION + EXPOSURE + FILES + PLATFORM)

    big = list(common)
    for base in NUMERIC_BASES:
        big.extend(f"{base}{n}" for n in range(1, 11))
        big.extend(f"{base}_{n}" for n in range(1, 6))
        big.extend(f"{base}-{year}" for year in YEARS)
        big.extend(f"{base}_{year}" for year in YEARS)
        big.extend(f"{base}.{ext}" for ext in ("zip", "tar", "tar.gz", "sql", "bak", "old", "txt", "json"))
    for base in ("index", "main", "app", "home", "login", "admin", "config", "test"):
        big.extend(f"{base}.{ext}" for ext in ("php", "asp", "aspx", "jsp", "html", "htm", "json", "xml", "bak", "old", "txt", "swp"))
    big = _normalise(big)

    return {"small": small, "common": common, "big": big}


def main() -> None:
    for tier, entries in build().items():
        path = HERE / f"dirs-{tier}.txt"
        header = (
            f"# ReconTitan directory-enumeration wordlist: {tier} ({len(entries)} entries)\n"
            "# Generated by build_wordlists.py -- edit that file, not this one.\n"
        )
        path.write_text(header + "\n".join(entries) + "\n", encoding="utf-8")
        print(f"{path.name}: {len(entries)} entries")


if __name__ == "__main__":
    main()
