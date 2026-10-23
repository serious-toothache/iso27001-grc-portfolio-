# Evidence summary: run_20261023T194112Z

- **Account:** 111122223333 · **Region:** af-south-1 · **Source:** mock:mock_aws_environment.json
- **Collected:** 2026-10-23T19:41:12+00:00 · **As of:** 2026-10-23
- **Result:** 3 pass · 6 fail · 0 error

| Check | Annex A | Status | Summary | Evidence |
|---|---|---|---|---|
| IAM-01: IAM password policy meets baseline | A.5.17 | ❌ FAIL | 3 password policy setting(s) below baseline. | [`IAM-01.json`](IAM-01.json) |
| IAM-02: Root user has MFA enabled | A.8.2, A.8.5 | ✅ PASS | Root MFA is enabled. | [`IAM-02.json`](IAM-02.json) |
| IAM-03: All console users have MFA | A.8.5 | ❌ FAIL | 2 of 5 console user(s) have no MFA. | [`IAM-03.json`](IAM-03.json) |
| IAM-04: Active access keys rotated within 90 days | A.5.17 | ❌ FAIL | 1 of 3 active access key(s) exceed 90 days. | [`IAM-04.json`](IAM-04.json) |
| LOG-01: Multi-region CloudTrail with log file validation | A.8.15 | ❌ FAIL | No trail is multi-region, logging and integrity-validated. | [`LOG-01.json`](LOG-01.json) |
| S3-01: S3 Block Public Access enabled at account level | A.8.3 | ✅ PASS | All four account-level Block Public Access settings are on. | [`S3-01.json`](S3-01.json) |
| CRY-01: EBS encryption by default enabled | A.8.24 | ✅ PASS | New EBS volumes are encrypted by default. | [`CRY-01.json`](CRY-01.json) |
| NET-01: No security group exposes SSH/RDP to the internet | A.8.20 | ❌ FAIL | 1 internet-exposed admin port rule(s). | [`NET-01.json`](NET-01.json) |
| MON-01: GuardDuty threat detection enabled | A.8.16 | ❌ FAIL | GuardDuty is not enabled in this region. | [`MON-01.json`](MON-01.json) |

Integrity: each file's SHA-256 is recorded in [`manifest.json`](manifest.json). Re-hash a file and compare to detect tampering.
