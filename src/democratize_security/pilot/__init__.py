"""M4 pilot sources: fixture, v4 verifier, reference apps, controls and templates.

`fixture.py`, `verify.py`, the reference apps and `check_isolation.py` are copied
byte-for-byte into the generated `tasks/pilot/` variants, so they stay standalone.
"""

import ast
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROLS = HERE / "controls"
FIXTURES = ("plain", "protected")
FAMILIES = (
    "invoice-read",
    "invoice-search",
    "invoice-export",
    "invoice-update",
    "invoice-create",
    "invoice-summary",
)
# The route function each family's starter omits; the agent adds it back.
ENDPOINTS = {
    "invoice-read": "invoice",
    "invoice-search": "invoices",
    "invoice-export": "export",
    "invoice-update": "update_invoice",
    "invoice-create": "create_invoice",
    "invoice-summary": "summary",
}


def reference(fixture: str) -> bytes:
    """The complete reference app for a fixture variant."""
    if fixture not in FIXTURES:
        raise ValueError(f"fixture must be one of {FIXTURES}")
    return (HERE / f"reference_{fixture}.py").read_bytes()


def starter(fixture: str, family: str) -> bytes:
    """The reference app with exactly the family's route function removed."""
    source = reference(fixture).decode()
    tree = ast.parse(source)
    create = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_app")
    node = next(
        n for n in create.body if isinstance(n, ast.FunctionDef) and n.name == ENDPOINTS[family]
    )
    lines = source.splitlines(keepends=True)
    start = min([node.lineno, *(d.lineno for d in node.decorator_list)]) - 1
    end = node.end_lineno
    # Drop the one blank separator line that followed the removed function.
    if end < len(lines) and not lines[end].strip():
        end += 1
    return "".join(lines[:start] + lines[end:]).encode()
