import pytest

from fastapi.testclient import TestClient

from app.main import app
from parsers.architecture_parser import parse_architecture
from threat_engine.analyzer import analyze


ARCHITECTURE = """
name: ecommerce-api
components:
  - name: frontend
    type: web
    internet_facing: true
  - name: api
    type: backend
    internet_facing: true
  - name: database
    type: postgres
    sensitive_data: true
connections:
  - frontend -> api
  - api -> database
"""


def test_yaml_parser_and_rules_find_expected_threats():
    report = analyze(parse_architecture(ARCHITECTURE))
    titles = {threat.title for threat in report.threats}
    assert {"SQL Injection", "Authentication Bypass", "Database Data Exposure"} <= titles
    assert report.summary["HIGH"] >= 2
    assert report.threats[0].score >= report.threats[-1].score


def test_api_returns_report():
    response = TestClient(app).post("/v1/analyze", json={"architecture": {"name": "tiny", "components": [{"name": "api", "type": "api", "internet_facing": True}], "connections": []}})
    assert response.status_code == 200
    assert response.json()["application"] == "tiny"


def test_api_accepts_raw_yaml_documents():
  response = TestClient(app).post("/v1/analyze", json={"architecture": ARCHITECTURE})
  assert response.status_code == 200
  assert response.json()["application"] == "ecommerce-api"


def test_public_sensitive_storage_is_critical():
    report = analyze(parse_architecture({"name": "files", "components": [{"name": "api", "type": "api"}, {"name": "bucket", "type": "storage", "public": True, "sensitive_data": True}], "connections": ["api -> bucket"]}))
    assert any(threat.title == "Public Storage Exposure" and threat.severity == "CRITICAL" for threat in report.threats)


def test_attack_paths_traverse_multiple_hops_to_sensitive_assets():
  architecture = parse_architecture({
    "name": "checkout",
    "components": [
      {"name": "api", "type": "api", "internet_facing": True},
      {"name": "worker", "type": "worker"},
      {"name": "database", "type": "postgres", "sensitive_data": True},
    ],
    "connections": [
      {"source": "api", "target": "worker", "data_types": ["orders"], "encrypted": True},
      {"source": "worker", "target": "database", "data_types": ["payment data"], "encrypted": True},
    ],
  })
  report = analyze(architecture)
  assert any(path.path == ["api", "worker", "database"] for path in report.attack_paths)


def test_duplicate_component_names_are_rejected():
  with pytest.raises(ValueError, match="must be unique"):
    parse_architecture({"components": [{"name": "api", "type": "api"}, {"name": "api", "type": "worker"}]})


def test_unencrypted_sensitive_data_flow_is_reported():
  report = analyze(parse_architecture({
    "name": "payments",
    "components": [{"name": "api", "type": "api"}, {"name": "database", "type": "postgres", "sensitive_data": True}],
    "connections": [{"source": "api", "target": "database", "data_types": ["payment data"]}],
  }))
  assert any(threat.title == "Unencrypted Sensitive Data Flow" for threat in report.threats)


def test_duplicate_connections_are_rejected():
  with pytest.raises(ValueError, match="Connections must be unique"):
    parse_architecture({"components": [{"name": "api", "type": "api"}, {"name": "db", "type": "database"}], "connections": ["api -> db", "api -> db"]})
