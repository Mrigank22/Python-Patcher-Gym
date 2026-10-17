"""Mutation test: each task must reject realistic *incomplete* fixes.

Reward-hacking audits (``hack_audit.py``) prove a candidate cannot cheat the
grader's machinery. This complements them at the domain level: it feeds each
family a set of plausible, well-intentioned but still-insecure implementations
— the kind a weak model actually writes — and asserts the security probes catch
them (``solved == False``). A task whose probes pass a mutant has a blind spot
a trained model would learn to exploit, so finding these is the point.

Each mutant is tagged:
  * ``insecure`` — must NOT be solved;
  * ``secure``   — an alternative correct fix that SHOULD be solved at reward
    1.0 (guards against probes that only accept the reference's exact form);
  * ``partial``  — a fix that works and is not exploitable for this exact task
    but is not the recommended idiom; it may be ``solved`` yet the static
    rubric must keep its shaped reward below 1.0 (and binary mode scores it 0).

Exit code is non-zero if any mutant is misclassified.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.tasks import get_family  # noqa: E402
from cybersec_env.verifier import Verifier  # noqa: E402

# family -> list of (name, expect, source). {ep} / signature are filled per task.
MUTANTS = {
    "sqli": [
        # Manual single-quote doubling is, for this exact single-quoted SQLite
        # literal, not injectable (no backslash escaping, value stays quoted),
        # so the dynamic probes rightly pass it -- but it is fragile and
        # non-portable, so the static rubric must deny it the full 1.0.
        ("quote_doubling", "partial",
         "def lookup_user(conn, username):\n"
         "    safe = username.replace(\"'\", \"''\")\n"
         "    cur = conn.cursor()\n"
         "    cur.execute(\"SELECT id, name, email FROM users WHERE name = '%s'\" % safe)\n"
         "    return cur.fetchall()\n"),
        ("blacklist_keywords", "insecure",
         "def lookup_user(conn, username):\n"
         "    for bad in ('OR', 'DROP', ';', '--'):\n"
         "        if bad in username.upper():\n"
         "            return []\n"
         "    cur = conn.cursor()\n"
         "    cur.execute(\"SELECT id, name, email FROM users WHERE name = '%s'\" % username)\n"
         "    return cur.fetchall()\n"),
        ("parameterized_qmark", "secure",
         "def lookup_user(conn, username):\n"
         "    cur = conn.cursor()\n"
         "    cur.execute('SELECT id, name, email FROM users WHERE name = ?', (username,))\n"
         "    return cur.fetchall()\n"),
    ],
    "path_traversal": [
        ("dotdot_substring_only", "insecure",
         "import os\n"
         "def read_within(base_dir, user_path):\n"
         "    if '..' in user_path:\n"
         "        return ''\n"
         "    try:\n"
         "        with open(os.path.join(base_dir, user_path)) as f:\n"
         "            return f.read()\n"
         "    except OSError:\n"
         "        return ''\n"),
        ("startswith_no_sep", "insecure",
         "import os\n"
         "def read_within(base_dir, user_path):\n"
         "    full = os.path.realpath(os.path.join(base_dir, user_path))\n"
         "    if not full.startswith(os.path.realpath(base_dir)):\n"
         "        return ''\n"
         "    try:\n"
         "        with open(full) as f:\n"
         "            return f.read()\n"
         "    except OSError:\n"
         "        return ''\n"),
        ("commonpath_fix", "secure",
         "import os\n"
         "def read_within(base_dir, user_path):\n"
         "    base = os.path.realpath(base_dir)\n"
         "    full = os.path.realpath(os.path.join(base, user_path))\n"
         "    if os.path.commonpath([base, full]) != base:\n"
         "        return ''\n"
         "    try:\n"
         "        with open(full) as f:\n"
         "            return f.read()\n"
         "    except OSError:\n"
         "        return ''\n"),
    ],
    "ssrf": [
        ("startswith_scheme_host", "insecure",
         "def is_allowed_url(url, allowed_hosts):\n"
         "    return any(url.startswith('http://' + h) or url.startswith('https://' + h)\n"
         "               for h in allowed_hosts)\n"),
        ("blacklist_evil", "insecure",
         "def is_allowed_url(url, allowed_hosts):\n"
         "    return 'evil' not in url and any(h in url for h in allowed_hosts)\n"),
        ("urlsplit_fix", "secure",
         "from urllib.parse import urlsplit\n"
         "def is_allowed_url(url, allowed_hosts):\n"
         "    p = urlsplit(url)\n"
         "    if p.scheme not in ('http', 'https'):\n"
         "        return False\n"
         "    return p.hostname in set(allowed_hosts)\n"),
    ],
    "xss": [
        ("escape_lt_only", "insecure",
         "def render_comment(username, comment):\n"
         "    c = comment.replace('<', '&lt;')\n"
         "    u = username.replace('<', '&lt;')\n"
         "    return f'<li><b>{u}</b>: {c}</li>'\n"),
        ("strip_script_tag", "insecure",
         "def render_comment(username, comment):\n"
         "    c = comment.replace('<script>', '').replace('</script>', '')\n"
         "    return f'<li><b>{username}</b>: {c}</li>'\n"),
        ("markupsafe_like", "secure",
         "import html\n"
         "def render_comment(username, comment):\n"
         "    return '<li><b>' + html.escape(username) + '</b>: ' + html.escape(comment) + '</li>'\n"),
    ],
    "weak_hash": [
        ("salted_sha256", "insecure",
         "import hashlib\n"
         "def hash_password(password, salt):\n"
         "    return hashlib.sha256((salt + password).encode()).hexdigest()\n"),
        ("double_md5", "insecure",
         "import hashlib\n"
         "def hash_password(password, salt):\n"
         "    h = hashlib.md5((salt + password).encode()).hexdigest()\n"
         "    return hashlib.md5(h.encode()).hexdigest()\n"),
        ("scrypt_fix", "secure",
         "import hashlib\n"
         "def hash_password(password, salt):\n"
         "    return hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()\n"),
    ],
    "insecure_random": [
        ("seeded_random_token", "insecure",
         "import random, string\n"
         "def make_token(n):\n"
         "    alphabet = string.ascii_letters + string.digits\n"
         "    return ''.join(random.choice(alphabet) for _ in range(n))\n"),
        ("hash_of_random", "insecure",
         "import random, hashlib, string\n"
         "def make_token(n):\n"
         "    alphabet = string.ascii_letters + string.digits\n"
         "    base = ''.join(random.choice(alphabet) for _ in range(n))\n"
         "    return hashlib.sha256(base.encode()).hexdigest()[:n]\n"),
        ("systemrandom_fix", "secure",
         "import random, string\n"
         "def make_token(n):\n"
         "    alphabet = string.ascii_letters + string.digits\n"
         "    sr = random.SystemRandom()\n"
         "    return ''.join(sr.choice(alphabet) for _ in range(n))\n"),
    ],
    "unsafe_deser": [
        ("full_load_try", "insecure",
         "import yaml\n"
         "def load_config(text):\n"
         "    try:\n"
         "        return yaml.load(text, Loader=yaml.FullLoader)\n"
         "    except Exception:\n"
         "        return {}\n"),
        ("safeloader_fix", "secure",
         "import yaml\n"
         "def load_config(text):\n"
         "    try:\n"
         "        return yaml.load(text, Loader=yaml.SafeLoader)\n"
         "    except Exception:\n"
         "        return {}\n"),
    ],
    "code_injection": [
        ("eval_empty_builtins", "insecure",
         "def evaluate_expression(expr):\n"
         "    try:\n"
         "        return eval(expr, {'__builtins__': {}}, {})\n"
         "    except Exception:\n"
         "        return None\n"),
        ("ast_literal_eval", "secure",
         "import ast, operator\n"
         "_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,\n"
         "        ast.Div: operator.truediv, ast.USub: operator.neg, ast.Pow: operator.pow,\n"
         "        ast.Mod: operator.mod}\n"
         "def _ev(node):\n"
         "    if isinstance(node, ast.Expression): return _ev(node.body)\n"
         "    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)): return node.value\n"
         "    if isinstance(node, ast.BinOp) and type(node.op) in _OPS: return _OPS[type(node.op)](_ev(node.left), _ev(node.right))\n"
         "    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS: return _OPS[type(node.op)](_ev(node.operand))\n"
         "    raise ValueError('no')\n"
         "def evaluate_expression(expr):\n"
         "    try:\n"
         "        return _ev(ast.parse(expr, mode='eval'))\n"
         "    except Exception:\n"
         "        return None\n"),
    ],
}


def main():
    verifier = Verifier(timeout_s=10.0, reward_mode="shaped")
    rows, bad = [], []
    for fam, mutants in MUTANTS.items():
        inst = get_family(fam).generate(seed=7, difficulty=1)
        for name, expect, src in mutants:
            res = verifier.grade_source(inst.task_id, src)
            if expect == "insecure":
                ok = res.solved is False
            elif expect == "secure":
                ok = res.solved is True and res.reward == 1.0
            else:  # "partial": works but discouraged -> not full reward
                ok = res.reward < 1.0
            rows.append({"family": fam, "mutant": name, "expect": expect,
                         "solved": res.solved, "reward": round(res.reward, 3),
                         "correct": ok, "guard_reason": res.guard_reason,
                         "details": res.details})
            if not ok:
                bad.append(rows[-1])

    hdr = f"{'family':16s} {'mutant':24s} {'expect':9s} {'solved':7s} {'reward':7s} {'ok':3s}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        flag = "OK" if r["correct"] else "XX"
        print(f"{r['family']:16s} {r['mutant']:24s} {r['expect']:9s} "
              f"{str(r['solved']):7s} {r['reward']:<7.3f} {flag}")
    print("-" * len(hdr))
    def tally(kind):
        tot = sum(1 for r in rows if r["expect"] == kind)
        good = sum(1 for r in rows if r["expect"] == kind and r["correct"])
        return good, tot
    print(f"\ninsecure mutants caught:            {tally('insecure')[0]}/{tally('insecure')[1]}")
    print(f"alternative secure fixes @reward 1.0: {tally('secure')[0]}/{tally('secure')[1]}")
    print(f"partial fixes correctly capped <1.0:  {tally('partial')[0]}/{tally('partial')[1]}")
    if bad:
        print("\nMISCLASSIFIED (probe blind spots to fix):")
        for r in bad:
            print(f"  {r['family']}/{r['mutant']} expect={r['expect']} "
                  f"solved={r['solved']} — {r['details']}")

    outdir = ROOT / "results"
    outdir.mkdir(exist_ok=True)
    (outdir / "mutation_test.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nwrote {outdir/'mutation_test.json'}")
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    main()
