# AI Threat Modelling Engineer

A deterministic, explainable security analysis engine for application architectures. It models components and trust boundaries, detects STRIDE-aligned threats, scores risk, builds attack-path evidence, and returns remediation plus validation guidance before deployment.

To Access the port :https://congenial-system-q74xqp5rj5pj2p6w-8000.app.github.dev/

## Current slice

- JSON, YAML, and Python model input
- Pydantic architecture validation, including `source -> target` connections
- Deterministic rules for SQL injection, authentication bypass, API abuse, data exposure, public storage, excessive permissions, and prompt injection trust boundaries
- STRIDE categories, CWE mappings, explainable findings, and severity scoring
- FastAPI endpoint for report generation
- Pytest evaluation fixture based on an intentionally vulnerable ecommerce architecture

The rule engine is deliberately independent from an LLM. An AI/RAG layer can be added later to enrich evidence and recommendations without making detection non-deterministic.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest
uvicorn app.main:app --reload
```

Then POST an architecture to `http://127.0.0.1:8000/v1/analyze`:

```bash
curl -s http://127.0.0.1:8000/v1/analyze \
	-H 'content-type: application/json' \
	--data '{"architecture":{"name":"ecommerce-api","components":[{"name":"api","type":"backend","internet_facing":true},{"name":"database","type":"postgres","sensitive_data":true}],"connections":["api -> database"]}}'
```

The sample architecture is at [examples/ecommerce.yaml](examples/ecommerce.yaml). API documentation is available at `/docs` when the server is running.

## Roadmap

1. Add Mermaid and Terraform parsers behind the same `Architecture` model.
2. Persist OWASP, CWE, MITRE ATT&CK, and cloud-control evidence in PostgreSQL/pgvector.
3. Add an optional Ollama reasoning pass that must cite retrieved evidence.
4. Generate Terraform remediation patches and validate them with Checkov.
5. Add CI security gates and attack-path evaluation metrics.
