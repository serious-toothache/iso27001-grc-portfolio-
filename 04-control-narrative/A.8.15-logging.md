# Control Narrative: A.8.15 Logging

| | |
|---|---|
| **Organization** | Tausi Telehealth Ltd (fictional) |
| **Control ID** | TT-LOG-01 |
| **ISO/IEC 27001:2022** | Annex A 8.15 Logging · related: A.8.16 Monitoring activities, A.8.17 Clock synchronization, A.5.28 Collection of evidence |
| **Control owner** | Platform Lead |
| **Control type** | Preventive (tamper protection) and detective (alerting); automated |
| **Frequency** | Continuous; configuration tested weekly by automated check LOG-01 |
| **State described** | Target design after remediation of [GAP-06](../03-gap-assessment/README.md#4-findings) |

## 1. Control statement

All management activity in Tausi's AWS environment is recorded in every region, delivered to a central log store that cannot be altered or deleted for 400 days, and protected so that any tampering with the logs or the logging itself is detected and alerted on.

## 2. Risk addressed

Without complete, trustworthy logs, Tausi cannot detect unauthorized access to patient data, investigate an incident, or show a regulator what happened. Specific risks:

- An attacker operates in a region nobody is logging.
- An attacker with admin access deletes or edits logs to hide their activity.
- Logging is switched off and nobody notices.

## 3. How the control works

1. **Collection.** An AWS Organizations trail (`tausi-org-trail`) is configured as **multi-region**, so it captures management events in every region and every member account, including regions Tausi doesn't use today.
2. **Integrity.** **Log file validation** is enabled. CloudTrail delivers an hourly digest file containing a hash of each log file, signed by AWS. Any modified or deleted log file fails validation.
3. **Immutability.** Logs are delivered to a dedicated bucket in a separate log-archive account. The bucket uses **S3 Object Lock in compliance mode** with a 400-day retention period, so no one, including the root user, can delete or overwrite logs during retention.
4. **Confidentiality.** Logs are encrypted with a customer-managed **KMS key** whose key policy allows only CloudTrail to encrypt and only the security team role to decrypt.
5. **Alerting.** A CloudWatch metric filter raises a high-severity alert to on-call on `StopLogging`, `DeleteTrail`, `UpdateTrail` or `PutEventSelectors` events.
6. **Time.** All AWS services use Amazon Time Sync, so log timestamps are consistent (A.8.17).

## 4. Evidence produced

| Evidence | Source | How it's generated |
|---|---|---|
| Trail configuration and status | `cloudtrail:DescribeTrails`, `GetTrailStatus` | Automated: [LOG-01](../02-evidence-collection/collect_evidence.py), hashed JSON, weekly |
| Digest validation result | `aws cloudtrail validate-logs` | Auditor re-performance on sampled days |
| Object Lock configuration | `s3:GetObjectLockConfiguration` | Exported JSON at audit time |
| Tamper alerts and responses | Alert history and linked tickets | Incident tool export |

## 5. How I would test it

**Test of design** (is the control capable of working?)

1. **Inquiry:** walk through the logging design with the control owner.
2. **Inspection:** confirm the trail is multi-region and an organization trail, log file validation is on, the bucket has Object Lock in compliance mode with at least 400 days retention, and the KMS key policy is restricted.
3. **Inspection:** confirm the metric filter and alarm exist for each of the four tamper events.

**Test of operating effectiveness** (did it work throughout the period?)

1. **Re-performance:** run `collect_evidence.py` and confirm LOG-01 passes. Compare against the weekly CI evidence history to confirm it passed for the whole audit period, with no gaps.
2. **Re-performance:** select **5 random days** across the audit period and run `aws cloudtrail validate-logs --trail-arn <arn> --start-time <day> --end-time <day+1>`. Expect every log and digest file to validate.
3. **Observation:** in a sandbox account, call `StopLogging` on a test trail and confirm the alert reaches on-call within 15 minutes.
4. **Inspection:** for each tamper alert raised during the period, confirm a ticket exists and was investigated.

**What counts as an exception:** any week where LOG-01 failed or was not run, any digest validation failure, or any tamper alert without an investigated ticket.

## 6. Exceptions and escalation

If LOG-01 fails or a tamper alert fires, the on-call engineer opens a Sev-2 incident under the incident response plan (A.5.24 to A.5.26). The Platform Lead restores logging within 4 hours and records the gap window in the risk register.

---

## Why I wrote it this way

**Auditors test what you write.** Every sentence in section 3 is a claim the auditor will try to verify, so each one maps to a test in section 5. If I couldn't write a test for a claim, I removed the claim.

**Design and operation are different questions.** A control can be perfectly configured on audit day and have been off for two months beforehand. That's why the operating effectiveness tests look across the whole period, using the weekly CI evidence history, not just today's configuration.

**I described the target state and said so.** The current environment fails this control (GAP-06). Writing the narrative for the remediated design gives the engineering team a precise definition of "done" and gives the auditor the test plan in advance.
