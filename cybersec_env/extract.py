"""Pull a Python function out of a model completion.

Models wrap code in ``` fences, sometimes add prose, sometimes emit the bare
function. We prefer a fenced ```python block, fall back to any fenced block,
then to a heuristic ``def ...`` slice. Returns the extracted source and a
``format_ok`` flag used for a small format component in the reward.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_FENCE_PY = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_FENCE_ANY = re.compile(r"```\s*\n(.*?)```", re.DOTALL)


@dataclass
class Extracted:
    code: str
    format_ok: bool


def extract_code(completion: str, entrypoint: str) -> Extracted:
    if completion is None:
        return Extracted("", False)

    m = _FENCE_PY.search(completion)
    if m:
        return Extracted(m.group(1).strip(), True)

    m = _FENCE_ANY.search(completion)
    if m:
        return Extracted(m.group(1).strip(), True)

    # No fence: try to slice from the first top-level def/import to the end.
    lines = completion.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith(("def ", "import ", "from ")):
            start = i
            break
    if start is not None:
        return Extracted("\n".join(lines[start:]).strip(), False)

    return Extracted(completion.strip(), False)
