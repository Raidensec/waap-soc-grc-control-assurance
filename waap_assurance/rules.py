import re
from collections import defaultdict
from datetime import datetime
from typing import Iterable
from urllib.parse import unquote

from .models import Detection, DetectionRule, WafEvent


SIGNATURE_RULES = (
    DetectionRule(
        "WAAP-SQLI-001", "SQL injection indicator", "High", "High",
        ("A03:2021 Injection",), ("T1190",), ("ID.RA", "DE.AE", "RS.AN", "RS.MA"),
        ("5.25", "5.26", "5.28", "8.15", "8.16", "8.23"),
        "Confirm the origin response and review adjacent requests before containment.",
        re.compile(r"(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|\bwaitfor\s+delay\b)", re.I),
    ),
    DetectionRule(
        "WAAP-XSS-001", "Cross-site scripting indicator", "High", "High",
        ("A03:2021 Injection",), ("T1190",), ("ID.RA", "DE.AE", "RS.AN", "RS.MA"),
        ("5.25", "5.26", "5.28", "8.15", "8.16", "8.23"),
        "Check whether the request reached the application and inspect related sessions.",
        re.compile(r"(?:<\s*script\b|javascript\s*:|\bon[a-z]+\s*=)", re.I),
    ),
    DetectionRule(
        "WAAP-PATH-001", "Path traversal indicator", "High", "High",
        ("A01:2021 Broken Access Control",), ("T1190",), ("ID.RA", "DE.AE", "RS.AN", "RS.MA"),
        ("5.25", "5.26", "5.28", "8.15", "8.16", "8.23"),
        "Validate the WAF decision and check for access to files outside the web root.",
        re.compile(r"(?:\.\./|\\\.\.\\|%2e%2e(?:/|%2f))", re.I),
    ),
    DetectionRule(
        "WAAP-CMD-001", "Command injection indicator", "Critical", "High",
        ("A03:2021 Injection",), ("T1190",), ("ID.RA", "DE.AE", "RS.AN", "RS.MA", "RS.MI"),
        ("5.25", "5.26", "5.28", "8.15", "8.16", "8.23"),
        "Escalate immediately if allowed; preserve origin and host telemetry for investigation.",
        re.compile(r"(?:;|\||&&|\$\()\s*(?:id|whoami|uname|curl|wget|powershell|cmd(?:\.exe)?\b)", re.I),
    ),
)

LOGIN_RULE = DetectionRule(
    "WAAP-AUTH-001", "Repeated failed authentication", "High", "Medium",
    ("A07:2021 Identification and Authentication Failures",), ("T1110",),
    ("ID.RA", "DE.CM", "DE.AE", "RS.MA"), ("5.25", "5.26", "8.15", "8.16"),
    "Check for successful logins from the same source and review account lockout controls.",
)
BURST_RULE = DetectionRule(
    "WAAP-RATE-001", "High request-rate burst", "High", "Medium",
    (), ("T1498.001",), ("ID.RA", "DE.CM", "DE.AE", "RS.MA", "RS.CO"),
    ("5.25", "5.26", "5.28", "8.15", "8.16", "8.23"),
    "Compare the burst with baseline traffic and confirm customer or origin impact before escalation.",
)
AUTH_ROUTES = {"/login", "/signin", "/auth"}
AUTH_FAILURE_CODES = {401, 403}
# Inclusive cutoffs are deliberate: one fewer matching record does not cross the threshold.
AUTH_FAILURE_THRESHOLD = 5
REQUEST_BURST_THRESHOLD = 20


def detect(events: Iterable[WafEvent]) -> list[Detection]:
    event_list = list(events)
    return signature_detections(event_list) + login_failure_detections(event_list) + request_bursts(event_list)


def signature_detections(events: Iterable[WafEvent]) -> list[Detection]:
    detections: list[Detection] = []
    for event in events:
        decoded_path = unquote(event.path)
        for rule in SIGNATURE_RULES:
            if rule.pattern and rule.pattern.search(decoded_path):
                detections.append(Detection(rule, (event,)))
    return detections


def login_failure_detections(events: Iterable[WafEvent]) -> list[Detection]:
    failed_logins = [event for event in events if is_failed_login(event)]
    groups = group_by_utc_minute(failed_logins)
    return threshold_detections(groups, LOGIN_RULE, AUTH_FAILURE_THRESHOLD)


def request_bursts(events: Iterable[WafEvent]) -> list[Detection]:
    groups = group_by_utc_minute(events)
    return threshold_detections(groups, BURST_RULE, REQUEST_BURST_THRESHOLD)


def is_failed_login(event: WafEvent) -> bool:
    route = event.path.split("?", maxsplit=1)[0].lower().rstrip("/") or "/"
    return route in AUTH_ROUTES and event.status_code in AUTH_FAILURE_CODES


def group_by_utc_minute(events: Iterable[WafEvent]) -> dict[tuple[str, str, datetime], list[WafEvent]]:
    groups: dict[tuple[str, str, datetime], list[WafEvent]] = defaultdict(list)
    for event in events:
        minute = event.timestamp.replace(second=0, microsecond=0)
        groups[(event.source_ip, event.host, minute)].append(event)
    return dict(groups)


def threshold_detections(
    groups: dict[tuple[str, str, datetime], list[WafEvent]],
    rule: DetectionRule,
    threshold: int,
) -> list[Detection]:
    return [Detection(rule, tuple(group)) for group in groups.values() if len(group) >= threshold]
