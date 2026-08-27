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


def test_public_sensitive_storage_is_critical():
    report = analyze(parse_architecture({"name": "files", "components": [{"name": "api", "type": "api"}, {"name": "bucket", "type": "storage", "public": True, "sensitive_data": True}], "connections": ["api -> bucket"]}))
    assert any(threat.title == "Public Storage Exposure" and threat.severity == "CRITICAL" for threat in report.threats)
