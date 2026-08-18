"""Product name to CPE mapping for version-aware CVE matching.

A CVE does not apply to a product because its description happens to mention
the product's name. It applies to specific product *versions*, which NVD
records as CPE (Common Platform Enumeration) configurations with explicit
version ranges. Matching on those ranges is the difference between "this CVE
mentions nginx" and "this CVE affects the nginx you are running".

This module maps the fingerprinter's display names onto the vendor/product
pairs NVD actually indexes, because the two rarely agree: nginx is indexed
under the vendor ``f5``, WordPress under ``wordpress``, and jQuery under
``jquery``. A name with no entry here is not guessed at -- an invented CPE
would silently match nothing and look identical to "no vulnerabilities found".
"""

from __future__ import annotations

import re

#: Display name (lowercased) -> (vendor, product) as indexed by NVD.
CPE_CATALOGUE: dict[str, tuple[str, str]] = {
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "tomcat": ("apache", "tomcat"),
    "openresty": ("openresty", "openresty"),

    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    # CPE 2.3 escapes "!" in a product name, so the literal is joomla\!
    "joomla": ("joomla", r"joomla\!"),
    "magento": ("magento", "magento"),
    "shopify": ("shopify", "shopify"),
    "typo3": ("typo3", "typo3"),
    "ghost": ("ghost", "ghost"),

    "php": ("php", "php"),
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "ruby on rails": ("rubyonrails", "rails"),
    "rails": ("rubyonrails", "rails"),
    "express": ("openjsf", "express"),
    "asp.net": ("microsoft", "asp.net"),
    "spring": ("vmware", "spring_framework"),
    "flask": ("palletsprojects", "flask"),

    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "angularjs": ("angularjs", "angular.js"),
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue"),
    "vue": ("vuejs", "vue"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "lodash": ("lodash", "lodash"),

    "openssl": ("openssl", "openssl"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
}

#: NVD version components are numeric-dotted; trailing build metadata breaks a match.
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def normalise_version(version: str | None) -> str:
    """Reduce a detected version to the numeric form NVD indexes.

    ``1.18.0-ubuntu`` and ``1.18.0 (Ubuntu)`` both become ``1.18.0``. An
    unparseable value returns empty so the caller falls back to a
    product-level query rather than querying a CPE that cannot match.
    """
    if not version:
        return ""
    match = _VERSION_RE.match(str(version).strip())
    return match.group(1) if match else ""


def lookup(product_name: str) -> tuple[str, str] | None:
    """Return the (vendor, product) CPE pair for a display name, or None."""
    if not product_name:
        return None
    key = str(product_name).strip().lower()
    if key in CPE_CATALOGUE:
        return CPE_CATALOGUE[key]
    # "Apache/2.4.41" and "nginx/1.18.0" style labels.
    head = re.split(r"[/\s]", key, maxsplit=1)[0].strip()
    return CPE_CATALOGUE.get(head)


def build_cpe(vendor: str, product: str, version: str = "") -> str:
    """Build a CPE 2.3 string. An empty version becomes the ``*`` wildcard."""
    return f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"


def cpe_for(product_name: str, version: str | None = None) -> tuple[str, str] | None:
    """Map a detected product to (cpe_string, normalised_version).

    Returns None when the product is unknown to the catalogue, so the caller
    can degrade to a clearly-labelled keyword search instead of inventing a
    CPE that would match nothing.
    """
    pair = lookup(product_name)
    if pair is None:
        return None
    vendor, product = pair
    clean_version = normalise_version(version)
    return build_cpe(vendor, product, clean_version), clean_version
