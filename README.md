# SOC Sentinel Lab

An entry-level SOC portfolio project that simulates a small SIEM detection pipeline. It ingests authentication logs, detects common attack patterns, assigns a severity, and produces analyst-ready alerts.

## What this demonstrates

- Log analysis and normalization
- SIEM-style correlation rules
- MITRE ATT&CK mapping
- Alert triage with severity and recommended actions
- Clear reporting for a SOC analyst portfolio

## Detection coverage

| Detection | Logic | MITRE ATT&CK |
| --- | --- | --- |
| Brute-force attempt | 5+ failed logins from one IP in 10 minutes | T1110 – Brute Force |
| Successful login after failures | Successful login from an IP after 3+ failures in 15 minutes | T1110 / T1078 |
| Impossible travel | One account signs in from two countries within 60 minutes | T1078 – Valid Accounts |
| Privileged account login | Successful sign-in by an administrator account | T1078 – Valid Accounts |

## Quick start

Requires Python 3.10+ and uses only the standard library.

```powershell
cd soc-sentinel-lab
python soc_detector.py --input sample_logs.jsonl --output alerts.json
```

View the generated results:

```powershell
Get-Content alerts.json
```

## Project flow

```text
Authentication logs -> Normalization -> Detection rules -> Enriched alerts -> Analyst triage
```

## Portfolio talking points

> Built a Python-based SOC detection lab that correlates authentication events to identify brute-force attacks, compromised credentials, impossible travel, and privileged access. Each alert is enriched with severity, MITRE ATT&CK techniques, evidence, and recommended first-response steps.

For a walkthrough of the simulated incident, read [ANALYST_REPORT.md](ANALYST_REPORT.md).

## Suggested next improvements

1. Ingest Windows Event ID 4624/4625 or Sysmon logs.
2. Store events and alerts in Elasticsearch or Splunk.
3. Send high-severity alerts to Slack/Teams/email.
4. Add IP reputation enrichment through a threat-intelligence API.

## Safe-use note

The included data is entirely fictional and intended for defensive learning and portfolio use.
