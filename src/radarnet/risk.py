from __future__ import annotations

from dataclasses import asdict, dataclass

from .model import Network, Node, Service


@dataclass(frozen=True)
class RiskReport:
    network_name: str
    score: int
    max_score: int
    severity: str
    findings: tuple[str, ...]

    @property
    def ratio(self) -> float:
        return 0.0 if self.max_score == 0 else round(self.score / self.max_score, 4)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["ratio"] = self.ratio
        return data


SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _service_risk(service: Service) -> tuple[int, list[str]]:
    score = 0
    findings: list[str] = []

    if service.public:
        score += 3
        findings.append(f"{service.name}:{service.port} is public")
    if not service.encrypted:
        score += 3
        findings.append(f"{service.name}:{service.port} is unencrypted")
    if not service.authenticated:
        score += 2
        findings.append(f"{service.name}:{service.port} has no authentication")

    score += service.criticality
    return score, findings


def _node_risk(node: Node) -> tuple[int, list[str]]:
    score = 0
    findings: list[str] = []

    for service in node.services:
        service_score, service_findings = _service_risk(service)
        score += service_score
        findings.extend([f"[{node.id}] {finding}" for finding in service_findings])

    if not node.services:
        findings.append(f"[{node.id}] has no tracked services (visibility gap)")
        score += 2

    return score, findings


def _severity(score: int, max_score: int) -> str:
    ratio = 0 if max_score == 0 else score / max_score
    if ratio >= 0.75:
        return "critical"
    if ratio >= 0.50:
        return "high"
    if ratio >= 0.25:
        return "medium"
    return "low"


def score_network(network: Network) -> RiskReport:
    network.validate()

    findings: list[str] = []
    score = 0
    max_score = max(1, len(network.nodes) * 13)

    for node in network.nodes:
        node_score, node_findings = _node_risk(node)
        score += node_score
        findings.extend(node_findings)

    severity = _severity(score, max_score)
    return RiskReport(
        network_name=network.name,
        score=score,
        max_score=max_score,
        severity=severity,
        findings=tuple(findings),
    )


def meets_severity_threshold(report: RiskReport, threshold: str) -> bool:
    if threshold not in SEVERITY_ORDER:
        raise ValueError(f"Invalid threshold '{threshold}'. Use one of: {', '.join(SEVERITY_ORDER)}")
    return SEVERITY_ORDER.index(report.severity) >= SEVERITY_ORDER.index(threshold)
