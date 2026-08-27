from dataclasses import dataclass

from threat_engine.models import Architecture, Severity, Threat


@dataclass(frozen=True)
class RuleFinding:
    title: str
    category: str
    severity: Severity
    asset: str
    cwe: str
    path: list[str]
    rationale: str
    control: str
    validation: str
    score: int


def detect(architecture: Architecture) -> list[RuleFinding]:
    components = {component.name: component for component in architecture.components}
    findings: list[RuleFinding] = []
    for link in architecture.connections:
        source = components.get(link.source)
        target = components.get(link.target)
        if not source or not target:
            continue
        path = [link.source, link.target]
        source_is_api = source.type.lower() in {"api", "backend", "service"}
        target_is_database = target.type.lower() in {"database", "postgres", "mysql", "sql", "mongodb"}
        if source_is_api and target_is_database:
            findings.extend([
                RuleFinding("SQL Injection", "Tampering", Severity.HIGH, target.name, "CWE-89", path, "An internet-reachable application component connects directly to a database.", "Use parameterised queries and least-privilege database credentials.", "Run SQL injection tests against API endpoints and review query construction.", 16),
                RuleFinding("Database Data Exposure", "Information Disclosure", Severity.HIGH if target.sensitive_data else Severity.MEDIUM, target.name, "CWE-200", path, "A compromise of the application path could expose database records.", "Encrypt sensitive data, restrict network access, and enforce row- or tenant-level authorization.", "Verify encryption, network policy, and authorization with an access-control test.", 16 if target.sensitive_data else 10),
            ])
        if source_is_api and not source.authentication:
            findings.append(RuleFinding("Authentication Bypass", "Spoofing", Severity.HIGH, source.name, "CWE-287", path, "The application component has no declared authentication control.", "Require strong authentication and authorization on every sensitive endpoint.", "Test unauthenticated and cross-user requests against protected endpoints.", 15))
        if source_is_api and source.authentication and not source.authorization:
            findings.append(RuleFinding("Authorization Bypass", "Elevation of Privilege", Severity.HIGH, source.name, "CWE-862", path, "Authentication is declared, but no authorization policy is declared for the application component.", "Enforce resource-level authorization and deny access by default.", "Test horizontal and vertical privilege escalation across protected endpoints.", 14))
        if source_is_api and source.internet_facing and not source.audit_logging:
            findings.append(RuleFinding("Insufficient Audit Logging", "Repudiation", Severity.MEDIUM, source.name, "CWE-778", path, "An internet-facing application has no declared audit logging control.", "Record security-relevant actions with tamper-resistant retention and alerting.", "Verify login, authorization, data-change, and administrator events are logged and attributable.", 8))
        if source.internet_facing or link.source.lower() == "internet":
            if source_is_api:
                findings.append(RuleFinding("API Abuse", "Denial of Service", Severity.MEDIUM, source.name, "CWE-770", path, "An API is exposed to an untrusted network.", "Apply rate limits, request validation, quotas, and abuse monitoring.", "Run load and rate-limit tests from an untrusted client.", 9))
        if target.public and target.type.lower() in {"storage", "blob", "bucket", "object-storage"}:
            findings.append(RuleFinding("Public Storage Exposure", "Information Disclosure", Severity.CRITICAL if target.sensitive_data else Severity.HIGH, target.name, "CWE-942", path, "Storage is marked public and may contain data reachable from the application.", "Disable anonymous public access and enforce identity-based access policies.", "Run Checkov or an equivalent policy scan and attempt anonymous access.", 20 if target.sensitive_data else 15))
        if target.permissions and any(permission.lower() in {"*", "admin", "owner"} for permission in target.permissions):
            findings.append(RuleFinding("Excessive Cloud Permissions", "Elevation of Privilege", Severity.HIGH, target.name, "CWE-269", path, "The connected component has broad permissions that increase blast radius after compromise.", "Apply least privilege with scoped, resource-specific permissions.", "Run an IAM policy scan and verify denied access to unrelated resources.", 17))
        if target.type.lower() in {"llm", "third-party", "external-api"}:
            findings.append(RuleFinding("Prompt Injection or Trust Boundary Abuse", "Tampering", Severity.HIGH, target.name, "CWE-74", path, "Untrusted data crosses into a third-party or language-model component.", "Treat external content as untrusted, isolate tools, and constrain model output.", "Test with adversarial instructions and assert that tools cannot escape their policy.", 15))
        if target.sensitive_data and link.data_types and not link.encrypted:
            findings.append(RuleFinding("Unencrypted Sensitive Data Flow", "Information Disclosure", Severity.HIGH, target.name, "CWE-319", path, "Sensitive data types cross a connection without an encryption control.", "Use authenticated transport encryption and protect data at rest where applicable.", "Capture traffic in transit and verify encryption, certificate validation, and key rotation.", 15))
    return findings
