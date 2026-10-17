"""Registry and static (source-level) rubric for the task families."""

from __future__ import annotations

import ast
from typing import Dict, List, Type

from .base import TaskFamily, TaskInstance
from .families import ALL_FAMILIES

_REGISTRY: Dict[str, Type[TaskFamily]] = {f.name: f for f in ALL_FAMILIES}


def family_names() -> List[str]:
    return list(_REGISTRY)


def get_family(name: str) -> TaskFamily:
    if name not in _REGISTRY:
        raise KeyError(f"unknown family '{name}'. known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]()


def generate(task_id: str) -> TaskInstance:
    """Rebuild a :class:`TaskInstance` from its ``family-difficulty-seed`` id.

    Ids of imported benchmark tasks (``<source>-1-<index>``) resolve to the
    validated records in ``cybersec_env/data/imported/``.
    """
    family, difficulty, seed = _parse_task_id(task_id)
    if family in _REGISTRY:
        return get_family(family).generate(seed=seed, difficulty=difficulty)
    from . import imported

    if family in imported.imported_sources():
        return imported.build(family, seed)
    raise KeyError(f"unknown task source '{family}' in task id '{task_id}'")


def _parse_task_id(task_id: str):
    family, difficulty, seed = task_id.rsplit("-", 2)
    return family, int(difficulty), int(seed)


# ---------------------------------------------------------------------------
# Source-level static rubric
# ---------------------------------------------------------------------------
# Each family maps to a predicate over the candidate *source string*. These are
# secondary, gameable signals, so they are given low weight in the reward and
# are never sufficient on their own — the dynamic exploit probes are the
# authority. They exist to nudge small models toward the idiomatic fix and to
# surface "looks right but isn't" cases in audits.

def _attr_name(node: ast.AST):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _uses(source: str, names: tuple) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    found = set()
    for node in ast.walk(tree):
        n = _attr_name(node.func) if isinstance(node, ast.Call) else None
        if n:
            found.add(n)
            found.add(n.split(".")[-1])
    return any(name in found for name in names)


def _shell_true(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
    return False


STATIC_RULES = {
    # name -> (predicate(source) -> bool is_secure, human message)
    "sqli": (lambda s: not _naive_sql_format(s), "query must be parameterized, not string-formatted"),
    "code_injection": (lambda s: not _uses(s, ("eval", "exec")), "must not use eval/exec"),
    "path_traversal": (lambda s: _uses(s, ("os.path.realpath", "realpath", "os.path.abspath", "abspath", "resolve", "commonpath")),
                       "must canonicalize and contain the path"),
    "unsafe_deser": (lambda s: _uses(s, ("yaml.safe_load", "safe_load")) and not _uses(s, ("yaml.load", "load")) or _uses(s, ("safe_load",)),
                     "use yaml.safe_load"),
    "ssrf": (lambda s: _uses(s, ("urlparse", "urlsplit")), "parse the URL and compare the hostname"),
    "xss": (lambda s: _uses(s, ("html.escape", "escape", "markupsafe")), "escape untrusted text"),
    "weak_hash": (lambda s: _uses(s, ("pbkdf2_hmac", "scrypt", "hashpw", "hash_secret", "hash_secret_raw",
                                      "hash", "PBKDF2HMAC", "Scrypt"))
                  and not _uses(s, ("md5", "sha1", "hashlib.md5", "hashlib.sha1")),
                  "use a password KDF (PBKDF2, scrypt, bcrypt or argon2), not a fast digest"),
    "insecure_random": (lambda s: _uses(s, ("secrets.choice", "secrets.token_hex", "secrets.token_urlsafe", "os.urandom", "SystemRandom")),
                        "use the secrets module / os.urandom"),
}


def _naive_sql_format(source: str) -> bool:
    """True if the SQL string is built with %, .format or an f-string."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        # execute(... % ...) or execute(f"...")
        if isinstance(node, ast.Call) and _attr_name(node.func) and _attr_name(node.func).endswith("execute"):
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                    return True
                if isinstance(arg, ast.JoinedStr):
                    return True
                if isinstance(arg, ast.Call) and _attr_name(arg.func) and _attr_name(arg.func).endswith("format"):
                    return True
    return False


def static_secure(family: str, source: str) -> bool:
    rule = STATIC_RULES.get(family)
    if rule is None:
        return True
    try:
        return bool(rule[0](source))
    except Exception:
        return False


def static_message(family: str) -> str:
    rule = STATIC_RULES.get(family)
    return rule[1] if rule else ""
