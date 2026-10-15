# Assurance mapping notes

The mapping registry lives in [`../waap_assurance/rules.py`](../waap_assurance/rules.py). Each finding carries references that can help an analyst connect event monitoring and incident response to a GRC review.

## NIST CSF 2.0 categories

The project maps findings to the following NIST CSF 2.0 category references:

| ID | Category |
| --- | --- |
| ID.RA | Risk Assessment |
| DE.CM | Continuous Monitoring |
| DE.AE | Adverse Event Analysis |
| RS.MA | Incident Management |
| RS.AN | Incident Analysis |
| RS.MI | Incident Mitigation |
| RS.CO | Incident Response Reporting and Communication |

The category IDs and names follow the [NIST CSF 2.0 Core](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20). Rule-level mappings are contextual examples; they are not a completed organizational CSF profile.

## ISO/IEC 27001:2022 Annex A references

The rules reference selected Annex A IDs: `5.25`, `5.26`, `5.28`, `8.15`, `8.16`, and `8.23`. The mapping is an initial alignment aid for event assessment, incident handling, evidence, logging/monitoring, and web-filtering review. The project intentionally does not make applicability or effectiveness claims. An organization must validate references against its current standard, scope, risk assessment, and Statement of Applicability before using them for assurance work.

## How the evidence file should be read

`control_evidence.csv` creates one row for each alert, source event, and mapped reference. Each row includes the event's SHA-256 fingerprint and the status `Analyst review required`. This is traceability from a detection to a source record and reference; it does not mean the referenced control passed a test or that the evidence is sufficient for an audit.

## Mapping boundaries

- OWASP categories describe the attack class indicated by a request pattern; a match is not proof that a vulnerability exists in the target application.
- MITRE ATT&CK technique IDs provide investigation context; they do not establish attribution or attacker intent.
- The rate-burst rule is a request-volume heuristic, not a DDoS impact determination.
- Risk register scores prioritize analyst review within this demo and are not likelihood/impact calculations calibrated to an enterprise methodology.
