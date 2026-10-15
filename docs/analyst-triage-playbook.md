# Analyst triage playbook

Use this sequence for cases exported in `incident_reports.md` and `cases.csv`.

1. **Validate the alert.** Confirm the source event, host, timestamp, rule match, WAF action, and related events. Check whether the detection came from a specific request indicator or a minute-bucket threshold.
2. **Scope the activity.** Search adjacent WAF, reverse-proxy, application, identity, and network telemetry for the same source, target, route, and time window. Compare request volume with the service's normal baseline.
3. **Check impact.** Determine whether suspicious requests were blocked, challenged, or allowed, then verify origin responses and application-side effects. Do not infer compromise from a request signature or from a WAF action alone.
4. **Set severity and escalate.** Escalate promptly when suspicious requests were allowed, authentication activity is followed by a successful login, or a request burst affected availability. Follow the organization's incident severity matrix and change-approval process for containment.
5. **Preserve evidence.** Retain original source records with timestamps and event IDs. Compare the exported SHA-256 fingerprint against the retained JSONL line; store evidence in the organization's approved, access-controlled repository.
6. **Record the GRC follow-up.** Use mapped references to review logging coverage, alert handling, evidence retention, and response procedures with the control owner. Record applicability, test method, evidence sufficiency, owner, and remediation separately; the export does not decide those items.
7. **Write the update.** State what was observed, what the WAF did, whether origin impact is confirmed, actions taken, remaining unknowns, and the next owner/action. Keep customer-facing statements factual and time-bounded.

For the included sample records, every IP address and event is synthetic. Do not send the generated reports to customers or treat them as a real incident record.
