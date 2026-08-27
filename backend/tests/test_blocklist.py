"""Operator blocklists: refusing to scan a host, and refusing to serve a caller.

The blocklist is the control an operator reaches for when something must stop
*now* — a withdrawn permission, a host outside scope, an actor abusing the
deployment. Two properties matter more than features:

* it must not over-match. Blocking ``example.com`` must not block
  ``notexample.com``, or an operator loses hosts they never intended to.
* it must not silently stop working. A database outage must not read as "the
  list is empty", because an empty list means everything is permitted.
"""

from __future__ import annotations

import pytest

from app.services import blocklist


@pytest.fixture(autouse=True)
def _memory_backed(monkeypatch):
    """Run against an in-memory store rather than the real database."""
    store: dict[str, list[dict]] = {blocklist.TARGETS: [], blocklist.SOURCES: []}

    class _Col:
        def __init__(self, name): self.name = name
        def find(self, *a, **k): return list(store[self.name])
        def create_index(self, *a, **k): return None
        def update_one(self, flt, update, upsert=False):
            key, value = next(iter(flt.items()))
            rows = store[self.name]
            for row in rows:
                if row.get(key) == value:
                    row.update(update["$set"])
                    return None
            rows.append(dict(update["$set"]))
        def delete_one(self, flt):
            key, value = next(iter(flt.items()))
            before = len(store[self.name])
            store[self.name] = [r for r in store[self.name] if r.get(key) != value]
            return type("R", (), {"deleted_count": before - len(store[self.name])})()

    class _DB:
        def __getitem__(self, name): return _Col(name)

    monkeypatch.setattr(blocklist, "get_db", lambda: _DB())
    blocklist.invalidate()
    yield store
    blocklist.invalidate()


# ── Targets ─────────────────────────────────────────────────────────────────

def test_a_blocked_host_is_refused():
    blocklist.block_target("forbidden.example", reason="out of scope")
    entry = blocklist.target_block("forbidden.example")
    assert entry is not None
    assert entry["reason"] == "out of scope"


def test_subdomains_of_a_blocked_host_are_refused():
    """An operator blocking a company means the company, not one hostname."""
    blocklist.block_target("forbidden.example")
    for host in ("api.forbidden.example", "deep.sub.forbidden.example"):
        assert blocklist.target_block(host) is not None


def test_a_similar_name_is_not_caught():
    """Substring matching here would block hosts the operator never named."""
    blocklist.block_target("example.com")
    assert blocklist.target_block("notexample.com") is None
    assert blocklist.target_block("example.com.evil.net") is None


def test_a_parent_is_not_blocked_by_a_child():
    blocklist.block_target("api.example.com")
    assert blocklist.target_block("example.com") is None
    assert blocklist.target_block("api.example.com") is not None


def test_blocking_is_case_and_scheme_insensitive():
    blocklist.block_target("https://FORBIDDEN.example/path")
    assert blocklist.target_block("forbidden.example") is not None


def test_unblocking_takes_effect_immediately():
    blocklist.block_target("temp.example")
    assert blocklist.target_block("temp.example") is not None
    assert blocklist.unblock_target("temp.example") is True
    assert blocklist.target_block("temp.example") is None


def test_unblocking_something_absent_reports_false():
    assert blocklist.unblock_target("never-added.example") is False


def test_an_empty_host_is_rejected():
    with pytest.raises(ValueError):
        blocklist.block_target("   ")


# ── Enforcement reaches target validation ───────────────────────────────────

def test_validate_scan_target_refuses_a_blocked_host():
    """The check lives in the one function every scan path already calls."""
    from app.targeting import validate_scan_target

    blocklist.block_target("blocked.example", reason="withdrawn permission")
    ok, _host, error = validate_scan_target("blocked.example", resolve_dns=False)

    assert ok is False
    assert "blocklist" in error.lower()
    assert "withdrawn permission" in error


def test_validate_scan_target_still_allows_everything_else():
    from app.targeting import validate_scan_target

    blocklist.block_target("blocked.example")
    ok, _host, _error = validate_scan_target("example.com", resolve_dns=False)
    assert ok is True


# ── Sources ─────────────────────────────────────────────────────────────────

def test_a_single_address_is_blocked():
    blocklist.block_source("203.0.113.9", reason="abuse")
    assert blocklist.source_block("203.0.113.9") is not None
    assert blocklist.source_block("203.0.113.10") is None


def test_a_cidr_range_covers_its_members():
    blocklist.block_source("203.0.113.0/24")
    for ip in ("203.0.113.1", "203.0.113.9", "203.0.113.255"):
        assert blocklist.source_block(ip) is not None


def test_a_cidr_range_stops_at_its_boundary():
    blocklist.block_source("203.0.113.0/24")
    assert blocklist.source_block("203.0.114.1") is None
    assert blocklist.source_block("8.8.8.8") is None


def test_ipv6_is_supported():
    blocklist.block_source("2001:db8::/32")
    assert blocklist.source_block("2001:db8::1") is not None
    assert blocklist.source_block("2001:db9::1") is None


def test_a_non_address_source_matches_literally():
    """Sources like "testclient" are not addresses but still worth blocking."""
    blocklist.block_source("203.0.113.5")
    assert blocklist.source_block("testclient") is None


def test_a_malformed_source_is_rejected():
    with pytest.raises(ValueError, match="IP address or CIDR"):
        blocklist.block_source("not an address")


# ── Failure behaviour ───────────────────────────────────────────────────────

def test_a_database_outage_keeps_the_last_known_list(monkeypatch):
    """An empty list means "nothing is blocked"; an outage must not say that."""
    blocklist.block_target("forbidden.example")
    assert blocklist.target_block("forbidden.example") is not None

    def _broken():
        raise ConnectionError("mongo down")

    monkeypatch.setattr(blocklist, "get_db", _broken)
    blocklist.invalidate()

    assert blocklist.target_block("forbidden.example") is not None, \
        "an outage must not silently re-permit a blocked target"


def test_changes_require_a_database(monkeypatch):
    """Better to refuse the write than to accept it into a cache and lose it."""
    monkeypatch.setattr(blocklist, "get_db", lambda: None)
    with pytest.raises(RuntimeError, match="unavailable"):
        blocklist.block_target("forbidden.example")
    with pytest.raises(RuntimeError, match="unavailable"):
        blocklist.block_source("203.0.113.9")
