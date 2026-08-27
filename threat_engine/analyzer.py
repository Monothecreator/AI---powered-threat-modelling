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
    components = {component.name: component for component in architecture.components}
    graph: dict[str, list[str]] = {name: [] for name in components}
    internet_targets: list[str] = []
    for connection in architecture.connections:
        if connection.source in components and connection.target in components:
            graph[connection.source].append(connection.target)
        elif connection.source.lower() == "internet" and connection.target in components:
            internet_targets.append(connection.target)

    entrypoints = [name for name, component in components.items() if component.internet_facing] + internet_targets
    paths: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()

    def walk(start: str, current: str, path: list[str]) -> None:
        component = components[current]
        if current != start and (component.sensitive_data or component.public):
            path_key = tuple(path)
            if path_key not in seen:
                severity = Severity.CRITICAL if component.public and component.sensitive_data else Severity.HIGH
                paths.append(AttackPath(path=path, blast_radius=severity, rationale=f"An internet-facing path reaches {current}, which is marked as a high-value asset."))
                seen.add(path_key)
        for neighbor in graph[current]:
            if neighbor not in path:
                walk(start, neighbor, [*path, neighbor])

    for entrypoint in entrypoints:
        walk(entrypoint, entrypoint, [entrypoint])
    return paths
