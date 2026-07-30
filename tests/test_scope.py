"""
tests/test_scope.py

Tests for phantom-mcp/auth/scope.py — scope validation logic.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add phantom-mcp/auth directly to path to avoid triggering the mcp package __init__
_AUTH_DIR = Path(__file__).parent.parent / "phantom-mcp"
_ROOT = Path(__file__).parent.parent
for p in [str(_AUTH_DIR), str(_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from auth.scope import is_in_scope, ScopeError, _strip_proto


# ─────────────────────────────────────────────────────────────────────────────
# is_in_scope tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIsInScope:
    def test_exact_domain_match(self):
        assert is_in_scope("example.com", ["example.com"])

    def test_exact_domain_case_insensitive(self):
        assert is_in_scope("EXAMPLE.COM", ["example.com"])

    def test_wildcard_subdomain_match(self):
        assert is_in_scope("sub.example.com", ["*.example.com"])

    def test_wildcard_deep_subdomain_match(self):
        assert is_in_scope("a.b.example.com", ["*.example.com"])

    def test_wildcard_apex_match(self):
        """*.example.com should also match example.com itself."""
        assert is_in_scope("example.com", ["*.example.com"])

    def test_wildcard_star_allows_all(self):
        assert is_in_scope("anything.com", ["*"])
        assert is_in_scope("192.168.1.100", ["*"])

    def test_cidr_match(self):
        assert is_in_scope("10.0.0.50", ["10.0.0.0/8"])

    def test_cidr_exact_boundary(self):
        assert is_in_scope("192.168.1.1", ["192.168.1.0/24"])

    def test_cidr_out_of_range(self):
        assert not is_in_scope("10.0.0.1", ["192.168.1.0/24"])

    def test_ip_exact_match(self):
        assert is_in_scope("203.0.113.5", ["203.0.113.5"])

    def test_no_match(self):
        assert not is_in_scope("evil.com", ["example.com", "*.good.com"])

    def test_empty_scope_list(self):
        assert not is_in_scope("example.com", [])

    def test_url_with_protocol_stripped(self):
        assert is_in_scope("https://example.com/path", ["example.com"])

    def test_url_with_port_stripped(self):
        assert is_in_scope("example.com:8443", ["example.com"])

    def test_multiple_scope_patterns_first_match(self):
        assert is_in_scope("sub.example.com", ["other.org", "*.example.com", "192.168.0.0/16"])

    def test_different_domain_no_match(self):
        assert not is_in_scope("notexample.com", ["example.com"])

    def test_partial_subdomain_no_match(self):
        """evilexample.com must NOT match *.example.com."""
        assert not is_in_scope("evilexample.com", ["*.example.com"])


# ─────────────────────────────────────────────────────────────────────────────
# _strip_proto helper
# ─────────────────────────────────────────────────────────────────────────────

class TestStripProto:
    def test_strips_https(self):
        assert _strip_proto("https://example.com/path?q=1") == "example.com"

    def test_strips_http(self):
        assert _strip_proto("http://example.com:8080/api") == "example.com"

    def test_passthrough_bare_domain(self):
        assert _strip_proto("example.com") == "example.com"

    def test_strips_port(self):
        assert _strip_proto("example.com:443") == "example.com"

    def test_strips_path(self):
        assert _strip_proto("example.com/some/path") == "example.com"


# ─────────────────────────────────────────────────────────────────────────────
# ScopeError raised correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeError:
    def test_scope_error_is_exception(self):
        err = ScopeError("out of scope")
        assert isinstance(err, Exception)
        assert "out of scope" in str(err)
