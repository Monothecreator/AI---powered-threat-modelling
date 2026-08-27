# System Design

```mermaid
flowchart LR
  Input[JSON or YAML architecture] --> Parser[Architecture parser]
  Parser --> Model[Validated internal model]
  Model --> Rules[Deterministic STRIDE rules]
  Rules --> Risk[Explainable risk scoring]
  Risk --> Report[Security report and attack paths]
  Report --> Remediation[Controls and validation checks]
  Knowledge[OWASP, CWE, MITRE, cloud controls] -. optional evidence .-> Report
  Report -. optional reasoning .-> LLM[Ollama reasoning layer]
```

The deterministic path is the system of record. Future AI and retrieval components enrich a finding only when they can provide evidence; they do not replace reproducible security rules.
