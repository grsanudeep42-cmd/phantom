"""
tests/conftest.py

Shared fixtures for the PHANTOM test suite.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

# Point at project root
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Force in-memory / temp SQLite for tests
os.environ.setdefault("PHANTOM_DATA_DIR", tempfile.mkdtemp(prefix="phantom_test_"))


# ─────────────────────────────────────────────────────────────────────────────
# Session fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def tmp_data_dir(tmp_path):
    """Temporary data dir per test."""
    os.environ["PHANTOM_DATA_DIR"] = str(tmp_path)
    from config.settings import settings
    settings.data_dir = tmp_path
    settings.ensure_dirs()
    yield tmp_path


@pytest.fixture(scope="function")
def fresh_db(tmp_data_dir):
    """Fresh SQLite DB per test."""
    from core.session import init_db
    init_db()
    yield tmp_data_dir


@pytest.fixture
def sample_session(fresh_db):
    """A real session in the test DB."""
    from core import session as db
    sess = db.create_session(
        target="example.com",
        mode="grey",
        scope=["example.com", "*.example.com"],
    )
    return sess


@pytest.fixture
def sample_session_with_findings(sample_session):
    """Session pre-populated with findings."""
    from core import session as db
    sid = sample_session.id

    db.add_finding(sid, "subdomain", "api.example.com", "info", "subfinder")
    db.add_finding(sid, "open_port", "Port 443/tcp open — nginx/1.24", "info", "nmap")
    db.add_finding(sid, "xss", "Reflected XSS in ?q= parameter", "high", "<script>alert(1)</script>")
    db.add_finding(sid, "sqli", "Blind SQLi in /login POST body", "critical", "' OR 1=1--")
    db.add_finding(sid, "csrf", "CSRF token missing on /profile/update", "medium", "")

    return sample_session
