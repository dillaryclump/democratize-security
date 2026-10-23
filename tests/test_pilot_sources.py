"""Offline structure of the pilot reference apps, starters and unsafe controls."""

import ast
import json

import pytest

from democratize_security.pilot import CONTROLS, ENDPOINTS, FAMILIES, FIXTURES, reference, starter

ROUTES = {
    "invoices": ("get", "/invoices"),
    "export": ("get", "/invoices/export"),
    "summary": ("get", "/invoices/summary"),
    "invoice": ("get", "/invoices/{invoice_id}"),
    "update_invoice": ("patch", "/invoices/{invoice_id}"),
    "create_invoice": ("post", "/invoices"),
}


def endpoints(source):
    create = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == "create_app"
    )
    found = {}
    for node in create.body:
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and getattr(decorator.func, "attr", None):
                    found[node.name] = (decorator.func.attr, decorator.args[0].value)
    return found


def module_without(source, names):
    tree = ast.parse(source)
    create = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_app")
    create.body = [
        n for n in create.body if not (isinstance(n, ast.FunctionDef) and n.name in names)
    ]
    return ast.dump(tree)


def test_families_and_endpoints():
    assert FAMILIES == (
        "invoice-read",
        "invoice-search",
        "invoice-export",
        "invoice-update",
        "invoice-create",
        "invoice-summary",
    )
    assert ENDPOINTS == {
        "invoice-read": "invoice",
        "invoice-search": "invoices",
        "invoice-export": "export",
        "invoice-update": "update_invoice",
        "invoice-create": "create_invoice",
        "invoice-summary": "summary",
    }
    assert FIXTURES == ("plain", "protected")


@pytest.mark.parametrize("fixture", ["plain", "protected"])
def test_reference_has_all_six_routes_in_safe_order(fixture):
    source = reference(fixture).decode()
    assert {k: v for k, v in endpoints(source).items() if k != "health"} == ROUTES
    order = list(endpoints(source))
    # Static paths must be registered before the {invoice_id} path.
    assert order.index("export") < order.index("invoice")
    assert order.index("summary") < order.index("invoice")


@pytest.mark.parametrize("fixture", ["plain", "protected"])
@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_starter_is_reference_minus_one_endpoint(fixture, family):
    source = reference(fixture).decode()
    removed = ENDPOINTS[family]
    text = starter(fixture, family).decode()
    assert removed not in endpoints(text)
    assert module_without(text, set()) == module_without(source, {removed})
    compile(text, "starter.py", "exec")


@pytest.mark.parametrize("fixture", ["plain", "protected"])
@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_unsafe_control_changes_only_its_endpoint(fixture, family):
    source = reference(fixture).decode()
    unsafe = (CONTROLS / f"{family}-{fixture}-unsafe.py").read_text()
    name = ENDPOINTS[family]
    assert module_without(unsafe, {name}) == module_without(source, {name})
    assert endpoints(unsafe)[name] == endpoints(source)[name]
    assert module_without(unsafe, set()) != module_without(source, set())


def test_plain_reference_filters_every_query_and_protected_none():
    plain, protected = reference("plain").decode(), reference("protected").decode()
    assert plain.count("tenant_id = %s") == 5
    assert "INSERT INTO public.invoices (tenant_id, description, amount_cents)" in plain
    assert "tenant_id" not in protected.split("def create_app", 1)[1].replace("app.tenant_id", "")
    assert "set_config('app.tenant_id'" in protected
    assert "set_config" not in plain


def test_expected_covers_every_variant():
    expected = json.loads((CONTROLS / "expected.json").read_text())
    assert set(expected) == set(ENDPOINTS)
    for family in ENDPOINTS:
        assert set(expected[family]) == {"plain", "protected"}
        for fixture in ("plain", "protected"):
            assert set(expected[family][fixture]) == {"nop", "unsafe"}
            for outcomes in expected[family][fixture].values():
                assert list(outcomes) == [
                    "fixture_configuration",
                    "authorized_reads",
                    "foreign_reads",
                    "list_search",
                    "exports",
                    "identity",
                    "spoofing",
                    "tenant_switching",
                    "aggregates",
                    "writes",
                ]
                assert set(outcomes.values()) <= {"pass", "fail"}
                assert outcomes["fixture_configuration"] == "pass"
                assert "fail" in outcomes.values()
