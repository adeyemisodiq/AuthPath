import json

import pytest

from authpath.config import load_scenario, ScenarioError
from tests.conftest import SCENARIO_PATH


def test_lab_scenario_loads():
    scenario = load_scenario(SCENARIO_PATH)
    assert len(scenario.subjects) == 4
    assert len(scenario.policies) == 5
    assert len(scenario.bindings) == 4
    assert scenario.identity_header == "X-User-ID"


def test_base_url_override():
    assert load_scenario(SCENARIO_PATH, base_url="http://127.0.0.1:1").base_url \
        == "http://127.0.0.1:1"


def _write(tmp_path, mutate):
    with open(SCENARIO_PATH, encoding="utf-8") as handle:
        data = json.load(handle)
    mutate(data)
    path = tmp_path / "s.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_missing_key_is_reported(tmp_path):
    path = _write(tmp_path, lambda d: d.pop("policies"))
    with pytest.raises(ScenarioError, match="policies"):
        load_scenario(path)


def test_duplicate_ids_rejected(tmp_path):
    path = _write(tmp_path, lambda d: d["subjects"].append(d["subjects"][0]))
    with pytest.raises(ScenarioError, match="Duplicate"):
        load_scenario(path)


def test_binding_to_unknown_resource_type_rejected(tmp_path):
    def mutate(d):
        d["bindings"][0]["resource"] = "spaceship"
    with pytest.raises(ScenarioError, match="spaceship"):
        load_scenario(_write(tmp_path, mutate))


def test_invalid_decision_rejected(tmp_path):
    def mutate(d):
        d["policies"][0]["decision"] = "perhaps"
    with pytest.raises(ValueError):
        load_scenario(_write(tmp_path, mutate))
