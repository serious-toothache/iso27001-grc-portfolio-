# 02 · Evidence Collection Script: Evidence as Code, Not Screenshots

**Files:** [`collect_evidence.py`](collect_evidence.py) · [`sample_data/`](sample_data) · [`tests/`](tests) · [`example-output/`](example-output/run_20261023T194112Z/summary.md)

## What I built

A Python script that pulls security configuration from an AWS account, tests it against 9 checks mapped to ISO/IEC 27001:2022 Annex A, and writes each result as a **timestamped, SHA-256-hashed JSON evidence file**.

| Check | Annex A | What it tests |
|---|---|---|
| IAM-01 | A.5.17 | Password policy meets baseline (14+ chars, complexity, reuse prevention) |
| IAM-02 | A.8.2, A.8.5 | Root user has MFA |
| IAM-03 | A.8.5 | Every console user has MFA (100% population, not a sample) |
| IAM-04 | A.5.17 | Active access keys rotated within 90 days |
| LOG-01 | A.8.15 | A multi-region CloudTrail trail is logging with log file validation |
| S3-01 | A.8.3 | S3 Block Public Access on at account level |
| CRY-01 | A.8.24 | EBS encryption by default |
| NET-01 | A.8.20 | No security group exposes SSH/RDP to 0.0.0.0/0 or ::/0 |
| MON-01 | A.8.16 | GuardDuty threat detection enabled |

## Run it (no AWS account needed)

```bash
cd 02-evidence-collection
python collect_evidence.py --mock sample_data/mock_aws_environment.json --as-of 2026-10-23
```

```
[FAIL ] IAM-01  A.5.17         3 password policy setting(s) below baseline.
[PASS ] IAM-02  A.8.2, A.8.5   Root MFA is enabled.
[FAIL ] IAM-03  A.8.5          2 of 5 console user(s) have no MFA.
[FAIL ] IAM-04  A.5.17         1 of 3 active access key(s) exceed 90 days.
[FAIL ] LOG-01  A.8.15         No trail is multi-region, logging and integrity-validated.
[PASS ] S3-01   A.8.3          All four account-level Block Public Access settings are on.
[PASS ] CRY-01  A.8.24         New EBS volumes are encrypted by default.
[FAIL ] NET-01  A.8.20         1 internet-exposed admin port rule(s).
[FAIL ] MON-01  A.8.16         GuardDuty is not enabled in this region.
```

Against a real account (read-only; attach the AWS managed `SecurityAudit` policy to the role you use):

```bash
pip install -r requirements.txt
python collect_evidence.py --profile audit-readonly --region af-south-1
```

Run the tests with `python -m pytest -q`.

## What one piece of evidence looks like

Every file in a run carries the same envelope ([full example](example-output/run_20261023T194112Z/IAM-03.json)):

```json
{
  "evidence_id": "run_20261023T194112Z-IAM-03",
  "check_id": "IAM-03",
  "iso27001_2022_annex_a": ["A.8.5"],
  "status": "FAIL",
  "findings": ["User 'carol.wanjiru' can sign in to the console without MFA.", "..."],
  "collected_at": "2026-10-23T19:41:12+00:00",
  "account_id": "111122223333",
  "api_calls": ["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
  "raw": { "console_users": ["..."] },
  "raw_sha256": "..."
}
```

`manifest.json` stores the SHA-256 of every evidence file, so anyone can re-hash a file and prove it hasn't been edited since collection.

## Why I built it this way

**A screenshot proves one moment on one screen.** It can't be re-run, doesn't show the whole population, and nobody can verify it wasn't edited. A JSON file with the API call that produced it, a timestamp and a hash fixes all four problems. An auditor can re-perform the test by running the same script.

**Collection is separated from evaluation.** `collect_live()` only fetches and normalizes data. The checks only evaluate it and never call AWS. That separation is what makes the checks unit-testable against a mock environment, and it means the same logic runs in an auditor's laptop, a CI pipeline or a scheduled job.

**`--as-of` makes results reproducible.** Time-based checks like key age change every day. Pinning the evaluation date means a test result from an audit period can be reproduced later.

**`--fail-on-findings` turns a control into a gate.** In CI, a failing check fails the build, which is how compliance moves from a yearly event to a continuous one.

## Limitations (stated honestly)

- Regional checks (security groups, GuardDuty, EBS) cover one region per run. A production version would loop over every enabled region.
- One account per run. A production version would assume a role into each account in the AWS Organization.
- Checks cover configuration, not operation. Proving GuardDuty findings are actually *acted on* still needs ticket evidence (see the test procedure for A.8.16 in [01-control-mapping](../01-control-mapping)).

## CI

[`.github/workflows/evidence.yml`](../.github/workflows/evidence.yml) runs the tests and the collector against the mock environment on every push and weekly, and uploads the evidence folder as a build artifact.
