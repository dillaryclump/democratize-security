import copy
import json
from pathlib import Path

import pytest

from democratize_security.cli import main
from democratize_security.contracts import ContractError, digest, load_campaign, plan, validate

EXAMPLE = Path(__file__).resolve().parents[1] / "campaigns/development.example.json"


@pytest.fixture
def campaign():
    return load_campaign(EXAMPLE)


def test_plan_is_stable_complete_and_offline(campaign):
    result = plan(campaign)
    assert result == plan(copy.deepcopy(campaign))
    assert len(result["trials"]) == 12
    assert len({t["trial_id"] for t in result["trials"]}) == 12
    assert result["execution_enabled"] is False
    assert all(t["status"] == "planned" for t in result["trials"])
    assert {t["condition"] for t in result["trials"]} == set(campaign["conditions"])


def test_changed_protocol_changes_all_trial_ids(campaign):
    original = plan(campaign)
    campaign["scoring_version"] = "changed"
    changed = plan(campaign)
    assert original["campaign_id"] != changed["campaign_id"]
    assert not (
        {t["trial_id"] for t in original["trials"]} & {t["trial_id"] for t in changed["trials"]}
    )


def test_digest_ignores_key_order():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_family_cannot_leak_across_splits(campaign):
    campaign["tasks"][1].update(family=campaign["tasks"][0]["family"], split="final")
    with pytest.raises(ContractError, match="cross splits"):
        validate(campaign)


@pytest.mark.parametrize(
    "key,value",
    [
        ("max_trials", 11),
        ("max_cost_usd_cents", -1),
        ("max_cost_usd_cents", True),
        ("timeout_seconds", 0),
        ("infrastructure_retries", 2),
        ("concurrency", 2),
        ("repair_attempts", 0.5),
    ],
)
def test_invalid_limits_rejected(campaign, key, value):
    campaign["limits"][key] = value
    with pytest.raises(ContractError):
        validate(campaign)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("source_revision", "main"),
        ("conditions", ["ordinary", "ordinary"]),
        ("conditions", ["made-up"]),
        ("conditions", [{}]),
        ("tasks", []),
        ("repetitions", False),
        ("hypothesis", "  "),
    ],
)
def test_invalid_top_level_values_rejected(campaign, key, value):
    campaign[key] = value
    with pytest.raises(ContractError):
        validate(campaign)


def test_duplicate_task_ids_rejected(campaign):
    campaign["tasks"][1]["id"] = campaign["tasks"][0]["id"]
    with pytest.raises(ContractError, match="duplicate task"):
        validate(campaign)


def test_invalid_task_revision_rejected(campaign):
    campaign["tasks"][0]["revision"] = "latest"
    with pytest.raises(ContractError, match="task.revision"):
        validate(campaign)


def test_unknown_and_missing_fields_rejected(campaign):
    campaign["accidental_option"] = True
    with pytest.raises(ContractError):
        validate(campaign)
    del campaign["accidental_option"]
    del campaign["limits"]
    with pytest.raises(ContractError):
        validate(campaign)


def test_nonfinite_model_setting_rejected(campaign):
    campaign["model"]["settings"]["temperature"] = float("nan")
    with pytest.raises(ContractError, match="finite"):
        validate(campaign)


def test_duplicate_json_keys_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version": 1, "schema_version": 2}')
    with pytest.raises(ContractError, match="duplicate JSON"):
        load_campaign(path)


def test_cli_validation(capsys):
    assert main(["validate", str(EXAMPLE)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] and result["trial_count"] == 12
    assert result["execution_enabled"] is False


def test_cli_plan(capsys):
    assert main(["plan", str(EXAMPLE)]) == 0
    assert len(json.loads(capsys.readouterr().out)["trials"]) == 12


def test_cli_bad_file_fails_cleanly(tmp_path, capsys):
    path = tmp_path / "invalid.json"
    path.write_text('{"broken"')
    assert main(["validate", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "Invalid campaign" in output.err


def test_no_execution_command():
    with pytest.raises(SystemExit) as error:
        main(["run", str(EXAMPLE)])
    assert error.value.code == 2
