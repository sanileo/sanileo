# Microsoft Sentinel Lab — Detection & Automated Response (in progress)

A self-built Microsoft Sentinel SIEM/SOAR lab on Azure, covering ingestion architecture, custom detection logic, automated incident response, and threat hunting. Built to deepen architectural understanding of SIEM design beyond prior analyst-side experience triaging Sentinel and Defender XDR alerts.

Every component below was built, broken, and re-verified with evidence — not assumed to work because a wizard completed without error.

## Architecture
<img width="949" height="411" alt="rg-creation" src="https://github.com/user-attachments/assets/da71e95d-60ad-41ae-a1b2-05f69394361b" />


```
Entra ID (sign-ins) ─┐
Azure Activity Log  ─┼─→ Log Analytics Workspace ─→ Analytics Rule (KQL) ─→ Incident
Defender for Cloud  ─┘                                                         │
                                                                                 ▼
                                              Logic Apps Playbook ←─ Automation Rule
```

**Ingestion:** Entra ID sign-in logs and Azure Activity (control-plane) logs via diagnostic settings; Defender for Cloud's free CSPM tier via native connector.

**Detection:** Custom KQL analytics rule on a 5-minute schedule, with Account/IP entity mapping so incidents carry correlated entities rather than flat alert text.

**Response:** A Sentinel automation rule triggers a Logic Apps playbook on incident creation, which posts an automated comment back to the incident — a real SOAR loop, not just a detection.

**Hunting:** Manual KQL queries for baseline identity activity and hypothesis-driven false-positive triage.

**Cost control:** Daily ingestion cap and 30-day retention set on the workspace *before* connecting any data source, since this runs on an Azure free-trial subscription.

## What's in this repo

| File | Description |
|---|---|
| `architecture.png` | Pipeline diagram (source → workspace → detection → response) |
| `kql/analytics-rule.kql` | Custom scheduled analytics rule — successful sign-in detection with entity mapping |
| `kql/hunting-baseline.kql` | Hunting query: sign-in volume by user and application (identity baseline) |
| `kql/hunting-bruteforce-check.kql` | Hunting query: repeated-failure pattern check across user/IP pairs |
| `logic-app/playbook-definition.json` | Logic Apps workflow definition for the incident-comment playbook |

## Analytics rule

```kql
SigninLogs
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
```

- **Schedule:** every 5 minutes, lookback 5 minutes
- **Threshold:** trigger on > 0 results
- **Entity mapping:** `Account` → identifier `Name`, value `UserPrincipalName`; `IP` → identifier `Address`, value `IPAddress`
- **Severity:** Informational (deliberately low-signal — built to validate the pipeline end-to-end, not as a production detection)

## Automated response

A Logic Apps playbook (`When a Microsoft Sentinel incident is created` → `Add comment to incident (V3)`) is wired to the rule above through a Sentinel automation rule scoped to it. Execution is verified by checking the incident's own activity timeline for the playbook's system-generated comment — confirmed working end-to-end, not just configured.

## Threat hunting

**Baseline — sign-in volume by user/app:**
```kql
SigninLogs
| summarize SignInCount = count() by UserPrincipalName, AppDisplayName
| sort by SignInCount desc
```

**Hypothesis test — repeated failures per user/IP pair (brute-force / spray check):**
```kql
SigninLogs
| where ResultType != "0"
| summarize FailureCount = count(), FailureTypes = make_set(ResultType) by UserPrincipalName, IPAddress
| where FailureCount > 1
| sort by FailureCount desc
```

This surfaced a pattern that looked like a textbook password-spray signature (one IP, six accounts, repeated failures). Decoding the actual Entra ID error codes (`50072`/`50074`/`50089` — MFA prompts and session expiry, not credential failures) confirmed it was lab-testing noise, not malicious activity — a deliberate exercise in not escalating on shape alone.

## Notable diagnostic findings

These are the debugging steps that actually built understanding, kept here because the troubleshooting is the point of a home lab, not a liability to hide:

- **Entity-mapping schema mismatch** — the portal's auto-suggested identifier (`UPNSuffix`) for the Account entity isn't valid; the platform's own validation error listed the accepted set (`FullName`, `Sid`, `Name`, `AadUserId`, `PUID`, `ObjectGuid`). Remapped to `Name`.
- **False "zero incidents" result** — ingestion lag, query correctness, and rule scheduling were all individually verified before finding the real cause: the Incidents view's default severity/priority filters silently excluded the rule's Informational-severity output. Nine incidents had existed the whole time.
- **AuditLogs export gap** — confirmed via the Entra ID portal's own log viewer that audit events were generated at the source but never exported to the workspace; isolated as an Entra ID licensing-tier limitation (no P1/P2), not a diagnostic-setting misconfiguration.
- **Defender XDR connector** — deliberately not connected. It requires a licensed Defender product generating real telemetry; the available trial path requires a credit card and auto-converts to a paid annual subscription after 30 days. Documented as a known, understood gap rather than incurring recurring cost for a personal lab.

## Environment

- Azure free-trial subscription, single Log Analytics workspace (`eastus`)
- Microsoft Sentinel (unified Defender portal)
- No paid licensing beyond the Azure trial credit

