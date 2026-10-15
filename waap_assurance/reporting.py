import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .engine import priority_for
from .mappings import CONTROL_REVIEW_STATUS, FRAMEWORK_NAMES, NIST_CSF_LABELS
from .models import Alert, Case, WafEvent


def write_outputs(alerts: list[Alert], cases: list[Case], event_count: int, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    write_alerts(alerts, output_dir / "alerts.csv")
    write_cases(cases, output_dir / "cases.csv")
    write_control_evidence(alerts, output_dir / "control_evidence.csv")
    write_risk_register(cases, output_dir / "risk_register.csv")
    write_incident_reports(cases, output_dir / "incident_reports.md")
    write_summary(alerts, cases, event_count, output_dir / "summary.json")


def write_alerts(alerts: list[Alert], target: Path) -> None:
    headers = ["alert_id", "case_id", "timestamp_utc", "source_ip", "host", "rule_id", "title", "severity", "priority", "risk_score", "confidence", "event_count", "waf_actions", "owasp", "mitre_attack", "nist_csf", "iso27001", "recommended_action", "triage_status"]
    rows = [alert_row(alert) for alert in alerts]
    write_csv(target, headers, rows)


def alert_row(alert: Alert) -> dict[str, object]:
    detection = alert.detection
    rule = detection.rule
    first_event = min(detection.events, key=lambda event: event.timestamp)
    return {
        "alert_id": alert.alert_id, "case_id": alert.case_id,
        "timestamp_utc": timestamp_text(first_event.timestamp), "source_ip": first_event.source_ip,
        "host": first_event.host, "rule_id": rule.rule_id, "title": rule.title,
        "severity": rule.severity, "priority": priority_for(alert.risk_score),
        "risk_score": alert.risk_score, "confidence": rule.confidence,
        "event_count": len(detection.events), "waf_actions": join_unique_strings(event.waf_action for event in detection.events),
        "owasp": join_unique_strings(rule.owasp), "mitre_attack": join_unique_strings(rule.mitre_attack),
        "nist_csf": join_unique_strings(rule.nist_csf), "iso27001": join_unique_strings(rule.iso27001),
        "recommended_action": rule.recommendation, "triage_status": "Open - analyst validation required",
    }


def write_cases(cases: list[Case], target: Path) -> None:
    headers = ["case_id", "priority", "risk_score", "source_ip", "host", "alert_count", "event_count", "first_seen_utc", "last_seen_utc", "owasp", "mitre_attack", "nist_csf", "iso27001", "triage_status"]
    write_csv(target, headers, (case_row(case) for case in cases))


def case_row(case: Case) -> dict[str, object]:
    events = case_events(case)
    rules = [alert.detection.rule for alert in case.alerts]
    return {
        "case_id": case.case_id, "priority": priority_for(case.risk_score),
        "risk_score": case.risk_score, "source_ip": case.source_ip, "host": case.host,
        "alert_count": len(case.alerts), "event_count": len({event.event_id for event in events}),
        "first_seen_utc": timestamp_text(min(event.timestamp for event in events)),
        "last_seen_utc": timestamp_text(max(event.timestamp for event in events)),
        "owasp": join_unique_strings(tag for rule in rules for tag in rule.owasp),
        "mitre_attack": join_unique_strings(tag for rule in rules for tag in rule.mitre_attack),
        "nist_csf": join_unique_strings(tag for rule in rules for tag in rule.nist_csf),
        "iso27001": join_unique_strings(tag for rule in rules for tag in rule.iso27001),
        "triage_status": "Open - analyst validation required",
    }


def write_control_evidence(alerts: list[Alert], target: Path) -> None:
    headers = ["evidence_id", "alert_id", "event_id", "evidence_sha256", "timestamp_utc", "source_ip", "host", "rule_id", "framework", "control_reference", "control_label", "review_status"]
    rows = (evidence_row(alert, event, framework, reference) for alert in alerts for event in alert.detection.events for framework, reference in control_references(alert))
    write_csv(target, headers, rows)


def evidence_row(alert: Alert, event: WafEvent, framework: str, reference: str) -> dict[str, object]:
    label = NIST_CSF_LABELS.get(reference, "Illustrative control reference") if framework == FRAMEWORK_NAMES["nist_csf"] else "Illustrative control reference"
    return {
        "evidence_id": f"EVD-{alert.alert_id}-{event.event_id}-{reference.replace('.', '')}",
        "alert_id": alert.alert_id, "event_id": event.event_id, "evidence_sha256": event.raw_sha256,
        "timestamp_utc": timestamp_text(event.timestamp), "source_ip": event.source_ip,
        "host": event.host, "rule_id": alert.detection.rule.rule_id, "framework": framework,
        "control_reference": reference, "control_label": label, "review_status": CONTROL_REVIEW_STATUS,
    }


def control_references(alert: Alert) -> Iterable[tuple[str, str]]:
    rule = alert.detection.rule
    return [(FRAMEWORK_NAMES["nist_csf"], code) for code in rule.nist_csf] + [(FRAMEWORK_NAMES["iso27001"], code) for code in rule.iso27001]


def write_risk_register(cases: list[Case], target: Path) -> None:
    headers = ["risk_id", "associated_case_id", "risk_statement", "priority_score", "priority", "activity_indicator", "origin_exposure_indicator", "evidence_event_ids", "control_references", "treatment_recommendation", "owner", "status"]
    write_csv(target, headers, (risk_row(case) for case in cases))


def risk_row(case: Case) -> dict[str, object]:
    events = case_events(case)
    rules = [alert.detection.rule for alert in case.alerts]
    allowed = any(event.waf_action == "allowed" for event in events)
    disposition = "may have reached the origin" if allowed else "was blocked or challenged by the WAF"
    risk_summary = f"Requests from {case.source_ip} against {case.host} triggered {len(case.alerts)} detection rule(s) and {disposition}. Validate impact and control effectiveness."
    return {
        "risk_id": case.case_id.replace("CASE-", "RISK-"), "associated_case_id": case.case_id,
        "risk_statement": risk_summary, "priority_score": case.risk_score,
        "priority": priority_for(case.risk_score), "activity_indicator": "Repeated (5+ events)" if len(events) >= 5 else "Observed",
        "origin_exposure_indicator": "Allowed action observed; impact unconfirmed" if allowed else "Blocked/challenged action observed; impact unconfirmed",
        "evidence_event_ids": join_unique_strings(sorted({event.event_id for event in events})),
        "control_references": case_control_refs(case),
        "treatment_recommendation": join_unique_strings(dict.fromkeys(rule.recommendation for rule in rules)),
        "owner": "Application owner (assign)", "status": "Needs analyst validation",
    }


def write_incident_reports(cases: list[Case], target: Path) -> None:
    sections = ["# WAAP Incident Triage Reports", "", "Generated from the supplied WAF event records. Validate each finding before operational use.", ""]
    sections.extend(case_report(case) for case in cases)
    target.write_text("\n".join(sections), encoding="utf-8")


def case_report(case: Case) -> str:
    events = case_events(case)
    rules = list(dict.fromkeys(alert.detection.rule for alert in case.alerts))
    evidence_ids = sorted({event.event_id for event in events})
    lines = [f"## {case.case_id} — {priority_for(case.risk_score)} (score {case.risk_score})", "",
             f"- Source: `{markdown_code_text(case.source_ip)}`", f"- Host: `{markdown_code_text(case.host)}`",
             f"- Window: {timestamp_text(min(event.timestamp for event in events))} to {timestamp_text(max(event.timestamp for event in events))}",
             f"- Evidence events: {', '.join(markdown_code_text(event_id) for event_id in evidence_ids)}",
             f"- WAF actions: {join_unique_strings(event.waf_action for event in events)}", "- Findings:"]
    lines.extend(f"  - `{rule.rule_id}` {rule.title} — {rule.severity}; {rule.confidence} confidence." for rule in rules)
    lines.extend(("- Recommended triage:", *[f"  - {rule.recommendation}" for rule in rules],
                  "- Governance references: " + case_control_refs(case), "- Status: Analyst validation required", ""))
    return "\n".join(lines)


def case_control_refs(case: Case) -> str:
    rules = [alert.detection.rule for alert in case.alerts]
    nist = join_unique_strings(code for rule in rules for code in rule.nist_csf)
    iso = join_unique_strings(code for rule in rules for code in rule.iso27001)
    return f"NIST CSF 2.0 {nist}; ISO/IEC 27001:2022 Annex A {iso} (illustrative mapping)"


def write_summary(alerts: list[Alert], cases: list[Case], event_count: int, target: Path) -> None:
    payload = {
        "event_count": event_count,
        "alert_count": len(alerts), "case_count": len(cases),
        "case_priorities": dict(sorted(Counter(priority_for(case.risk_score) for case in cases).items())),
        "alert_rule_counts": dict(sorted(Counter(alert.detection.rule.rule_id for alert in alerts).items())),
        "analyst_review_required": bool(alerts),
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_csv(target: Path, headers: list[str], rows: Iterable[dict[str, object]]) -> None:
    with target.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction="raise")
        writer.writeheader()
        writer.writerows(safe_row(row) for row in rows)


def safe_row(row: dict[str, object]) -> dict[str, object]:
    return {key: safe_csv_cell(cell_content) for key, cell_content in row.items()}


def safe_csv_cell(cell_content: object) -> object:
    if isinstance(cell_content, str) and cell_content.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + cell_content
    return cell_content


def case_events(case: Case) -> list[WafEvent]:
    unique = {event.event_id: event for alert in case.alerts for event in alert.detection.events}
    return list(unique.values())


def timestamp_text(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def join_unique_strings(strings: Iterable[str]) -> str:
    return "; ".join(dict.fromkeys(strings))


def markdown_code_text(raw_text: str) -> str:
    return raw_text.replace("`", "ˋ").replace("\n", " ").replace("\r", " ")
