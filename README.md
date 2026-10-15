# WAAP SOC & GRC Control Assurance Pipeline

A runnable Python command-line project that turns normalized WAF/HTTP telemetry into analyst-triage cases and a control-evidence package. It combines SOC workflows—detection, severity routing, incident reporting—with GRC artifacts: a risk register and traceable NIST CSF 2.0 / ISO/IEC 27001:2022 Annex A references.

The included records are synthetic and use documentation-only IP ranges. The framework references are illustrative; the project does not certify, assess, or claim compliance for an organization.

## What it does

- Validates JSON Lines (JSONL) input at the ingestion boundary, including timestamp, IP, HTTP method, status code, WAF action, field lengths, and duplicate event IDs.
- Detects request indicators for SQL injection, cross-site scripting, path traversal, command injection, repeated failed logins, and high request-rate bursts.
- Groups findings by source IP and host, assigns a transparent heuristic risk score, and creates analyst-ready cases.
- Exports evidence rows with SHA-256 fingerprints, NIST CSF 2.0 category references, ISO/IEC 27001:2022 Annex A control IDs, and review-required status.
- Produces CSV alert/case queues and a triage report, risk register, and machine-readable summary.

## Run the sample

Requires Python 3.10 or newer and uses only the Python standard library.

From this project directory:

```powershell
python --version
python -m waap_assurance --input data/sample_waf.jsonl --output output
```

The command creates an `output/` directory containing:

| File | Use |
| --- | --- |
| `alerts.csv` | Rule-level findings, severity, risk score, framework references, and next steps |
| `cases.csv` | Grouped analyst queue with priority, event counts, and first/last seen |
| `control_evidence.csv` | Event hashes and linked NIST/ISO references, each marked for analyst review |
| `risk_register.csv` | Case-based risk statements, indicators, treatment suggestions, and owner/status fields |
| `incident_reports.md` | Human-readable triage summaries for each case |
| `summary.json` | Processed-event, alert, case, and rule counts |

Malformed input stops the run with a line-numbered error and a non-zero exit status. Existing files with the same output names are replaced when a new run succeeds.

## Input schema

Each non-empty line must be a JSON object with unique field names and these fields:

| Field | Expected value |
| --- | --- |
| `event_id` | Unique, non-empty string, up to 128 characters |
| `timestamp` | ISO 8601 timestamp with a timezone; normalized to UTC |
| `source_ip` | IPv4 or IPv6 address |
| `host` | Non-empty host string, up to 255 characters |
| `method` | HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS |
| `path` | Request path beginning with `/`, up to 2,048 characters |
| `status_code` | Integer from 100 to 599 |
| `waf_action` | `allowed`, `blocked`, or `challenged` |
| `user_agent` | String up to 512 characters; an empty string is accepted |

Unrecognized fields are ignored. The importer does not read separate request-body, cookie, or authorization-header fields. Detection uses the supplied `path` value, including query text if the WAF source includes it there. Do not include secrets or customer data in portfolio samples.

## Detection and scoring

Signature rules inspect the URL-decoded request path once. Authentication and rate rules use fixed UTC-minute buckets, grouped by source IP and host. A minute with at least five failed requests to `/login`, `/signin`, or `/auth` (HTTP 401/403) raises an authentication alert. A source with at least 20 requests in one UTC minute raises a rate-burst alert. Cases group by source IP, host, and 30-minute UTC window. These are starting heuristics, not customer-specific baselines.

Alert risk scores use the rule severity base (Medium 40, High 65, Critical 85), add up to 15 points for repeated matching events, and add 15 points if at least one matching event was logged as `allowed`; scores are capped at 100. Case scores start from the highest alert score and add up to 20 points for additional alerts. Priority bands are Critical (85+), High (65–84), Medium (40–64), and Low (below 40). Confidence describes the strength of a pattern match or threshold signal, not the probability of compromise. Scores are explainable routing aids, not calibrated probabilities or formal enterprise risk ratings.

WAF action is treated as telemetry context. A `blocked` or `challenged` action does not prove an attack had no impact, and an `allowed` action does not prove compromise. Analyst validation remains required in every exported queue.

## Framework and evidence use

Each rule carries references to relevant OWASP Top 10:2021 categories, MITRE ATT&CK techniques, NIST CSF 2.0 categories, and selected ISO/IEC 27001:2022 Annex A control IDs. See [`docs/assurance-mappings.md`](docs/assurance-mappings.md) for scope and limitations. These references help organize a control review; they are not a control applicability decision, a statement of control effectiveness, an ISO audit result, or proof of compliance.

Each evidence row contains the source event ID and a SHA-256 fingerprint of the original JSONL line. The fingerprint can help detect changes when compared with the retained source line; it does not by itself establish source authenticity, a chain of custody, or immutable storage.

## Analyst workflow

Use [`docs/analyst-triage-playbook.md`](docs/analyst-triage-playbook.md) to validate an alert, investigate origin impact, decide when to escalate, preserve evidence, and write a concise incident update. The project processes supplied WAF telemetry offline; it does not connect to a commercial WAF/CDN, SIEM, ticketing system, customer account, or live network.

## References

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001.html)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [OWASP Top 10:2021](https://owasp.org/Top10/2021/)
