"""Guard tests: grader-escape constructs are rejected, normal fixes allowed."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.guard import scan

BLOCKED = [
    "import cybersec_env\ndef f(): return 1",
    "import os\nos.path.exists = lambda *a: False\ndef f(): return 1",
    "def f():\n    return ().__class__.__bases__[0].__subclasses__()",
    "import sys\ndef f():\n    sys.exit(0)",
    "def f():\n    return eval('1+1')",
    "import socket\ndef f(): return 1",
    "import subprocess\ndef f(): return 1",
    "def f():\n    return __import__('os')",
    "import importlib\ndef f(): return 1",
]

ALLOWED = [
    "import os\ndef read_within(b, u):\n    full = os.path.realpath(os.path.join(b, u))\n    return ''",
    "import hashlib\ndef hash_password(p, s):\n    return hashlib.sha256((s+p).encode()).hexdigest()",
    "from urllib.parse import urlparse\ndef is_allowed_url(u, a):\n    return urlparse(u).hostname in set(a)",
    "import html\ndef render_comment(u, c):\n    return f'<li>{html.escape(c)}</li>'",
    "import secrets, string\ndef make_token(n):\n    return ''.join(secrets.choice(string.ascii_letters) for _ in range(n))",
]


@pytest.mark.parametrize("src", BLOCKED)
def test_blocked(src):
    assert scan(src).ok is False


@pytest.mark.parametrize("src", ALLOWED)
def test_allowed(src):
    r = scan(src)
    assert r.ok is True, r.reason


def test_syntax_error_reported():
    r = scan("def f(:\n  pass")
    assert not r.ok
    assert "syntax" in r.reason
