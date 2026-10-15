import hashlib
import json
from collections import defaultdict
from datetime import datetime

from .models import Alert, Case, Detection


SEVERITY_SCORES = {"Medium": 40, "High": 65, "Critical": 85}
CASE_WINDOW_MINUTES = 30


def build_alerts(detections: list[Detection]) -> list[Alert]:
    alerts = []
    for detection in detections:
        first_event = min(detection.events, key=lambda event: event.timestamp)
        window_start = case_window_start(first_event.timestamp)
        case_id = stable_id("CASE", first_event.source_ip, first_event.host, window_start.isoformat())
        alert_id = stable_id("ALERT", case_id, detection.rule.rule_id, *sorted(event.event_id for event in detection.events))
        alerts.append(Alert(alert_id, case_id, detection, alert_risk_score(detection)))
    return sorted(alerts, key=lambda alert: (-alert.risk_score, alert.detection.events[0].timestamp))


def alert_risk_score(detection: Detection) -> int:
    base_score = SEVERITY_SCORES[detection.rule.severity]
    recurrence_score = min(15, (len(detection.events) - 1) * 3)
    allowed_score = 15 if any(event.waf_action == "allowed" for event in detection.events) else 0
    return min(100, base_score + recurrence_score + allowed_score)


def build_cases(alerts: list[Alert]) -> list[Case]:
    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[alert.case_id].append(alert)
    return sorted((make_case(case_id, case_alerts) for case_id, case_alerts in grouped.items()), key=lambda case: (-case.risk_score, case.case_id))


def make_case(case_id: str, alerts: list[Alert]) -> Case:
    events = [event for alert in alerts for event in alert.detection.events]
    first_event = min(events, key=lambda event: event.timestamp)
    score = min(100, max(alert.risk_score for alert in alerts) + min(20, (len(alerts) - 1) * 5))
    return Case(case_id, first_event.source_ip, first_event.host, tuple(alerts), score)


def stable_id(prefix: str, *parts: str) -> str:
    payload = json.dumps(parts, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def priority_for(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def case_window_start(timestamp: datetime) -> datetime:
    minute = (timestamp.minute // CASE_WINDOW_MINUTES) * CASE_WINDOW_MINUTES
    return timestamp.replace(minute=minute, second=0, microsecond=0)
