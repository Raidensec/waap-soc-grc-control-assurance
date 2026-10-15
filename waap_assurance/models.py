from dataclasses import dataclass
from datetime import datetime
from re import Pattern


@dataclass(frozen=True)
class WafEvent:
    event_id: str
    timestamp: datetime
    source_ip: str
    host: str
    method: str
    path: str
    status_code: int
    waf_action: str
    user_agent: str
    raw_sha256: str


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    severity: str
    confidence: str
    owasp: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    nist_csf: tuple[str, ...]
    iso27001: tuple[str, ...]
    recommendation: str
    pattern: Pattern[str] | None = None


@dataclass(frozen=True)
class Detection:
    rule: DetectionRule
    events: tuple[WafEvent, ...]


@dataclass(frozen=True)
class Alert:
    alert_id: str
    case_id: str
    detection: Detection
    risk_score: int


@dataclass(frozen=True)
class Case:
    case_id: str
    source_ip: str
    host: str
    alerts: tuple[Alert, ...]
    risk_score: int
