from collections import Counter

from threat_engine.models import AttackPath, Architecture, SecurityReport, Severity, Threat
from threat_engine.rules import detect


def analyze(architecture: Architecture) -> SecurityReport:
    findings = detect(architecture)
    threats = [Threat(id=f"THREAT-{index:03d}", title=finding.title, category=finding.category, severity=finding.severity, affected_asset=finding.asset, cwe=finding.cwe, attack_path=finding.path, rationale=finding.rationale, recommended_control=finding.control, validation=finding.validation, score=finding.score) for index, finding in enumerate(sorted(findings, key=lambda item: item.score, reverse=True), 1)]
    summary = {severity: sum(threat.severity == severity for threat in threats) for severity in Severity}
    attack_paths = _attack_paths(architecture, threats)
    return SecurityReport(application=architecture.name, threat_count=len(threats), summary=summary, threats=threats, attack_paths=attack_paths)


def _attack_paths(architecture: Architecture, threats: list[Threat]) -> list[AttackPath]:
    paths: list[AttackPath] = []
    for threat in threats:
        if threat.severity in {Severity.CRITICAL, Severity.HIGH} and len(threat.attack_path) == 2:
            paths.append(AttackPath(path=threat.attack_path, blast_radius=threat.severity, rationale=f"{threat.title} creates a {threat.severity.value.lower()} impact across this trust boundary."))
    return paths
