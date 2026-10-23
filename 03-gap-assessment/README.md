# 03 · Mock Gap Assessment: Tausi Telehealth Ltd vs ISO/IEC 27001:2022

**Files:** this report · [`gap-register.csv`](gap-register.csv) (full register, GitHub renders it as a table)

> Tausi Telehealth is a **fictional** Nairobi-based telehealth startup created for this portfolio. The AWS findings come from running the collector in [02-evidence-collection](../02-evidence-collection) against a simulated account. The ISMS findings come from simulated interviews and document requests.

## 1. Executive summary

Tausi Telehealth wants ISO/IEC 27001:2022 certification within 9 months to win a contract with a regional insurer. It handles patient health data on AWS.

**Tausi is not ready for certification today.** I identified **12 gaps**: 1 Critical, 8 High and 3 Medium.

Two kinds of problems need two kinds of fixes:

- **Security risk is concentrated in identity.** Two console users have no MFA, and one of them is a contractor with a 215-day-old access key. That combination (GAP-01, GAP-08) is the most likely path to a breach of patient data and should be fixed this month.
- **Certification risk is concentrated in the ISMS itself.** There is no risk methodology, no Statement of Applicability and no internal audit (GAP-02, GAP-04, GAP-05). These would be major nonconformities at a Stage 1 audit, regardless of how good the technical controls are.

The good news: most technical gaps are **low effort** (configuration changes measured in hours), and 3 of the 9 automated checks already pass (root MFA, S3 Block Public Access, EBS encryption by default).

## 2. Scope and method

| | |
|---|---|
| **Scope** | AWS production account `111122223333` (af-south-1); ISMS documentation; Clauses 4–10 and a risk-based sample of Annex A controls |
| **Standard** | ISO/IEC 27001:2022 |
| **Assessment date** | 23 October 2026 |
| **Technical testing** | 9 automated checks, 100% population, evidence run [`run_20261023T194112Z`](../02-evidence-collection/example-output/run_20261023T194112Z/summary.md) |
| **ISMS testing** | Simulated interviews (CTO, Head of Engineering) and document requests |

Every technical finding cites a hashed evidence file. No finding relies on a screenshot.

## 3. Rating method

`Risk score = Likelihood (1–5) × Impact (1–5)`

| Score | Rating | Expected response |
|---|---|---|
| 20–25 | Critical | Fix within 30 days; report to leadership now |
| 12–19 | High | Fix within 30–60 days |
| 6–11 | Medium | Fix within 90 days |
| 1–5 | Low | Accept or fix opportunistically |

Impact is weighted up for anything touching patient health data. Separately, a **certification blocker** flag marks clause-level gaps that would stop certification even if the security risk is moderate. A gap can be low-risk and still block the certificate.

## 4. Findings

| ID | Requirement | Finding | Evidence | Score | Rating | Blocker |
|---|---|---|---|---|---|---|
| GAP-01 | A.8.5 | 2 of 5 console users have no MFA, including a contractor | [IAM-03](../02-evidence-collection/example-output/run_20261023T194112Z/IAM-03.json) | 20 | 🔴 Critical | |
| GAP-02 | Cl. 6.1.2 | No documented risk assessment process or acceptance criteria | Interview, DR-03 | 16 | 🟠 High | ⛔ |
| GAP-03 | A.8.20 | SSH open to the internet on production app servers | [NET-01](../02-evidence-collection/example-output/run_20261023T194112Z/NET-01.json) | 16 | 🟠 High | |
| GAP-04 | Cl. 6.1.3 d) | No Statement of Applicability | DR-04 | 15 | 🟠 High | ⛔ |
| GAP-05 | Cl. 9.2 | No internal audit programme | Interview | 15 | 🟠 High | ⛔ |
| GAP-06 | A.8.15 | CloudTrail single-region, no log file validation | [LOG-01](../02-evidence-collection/example-output/run_20261023T194112Z/LOG-01.json) | 12 | 🟠 High | |
| GAP-07 | A.8.16 | GuardDuty not enabled | [MON-01](../02-evidence-collection/example-output/run_20261023T194112Z/MON-01.json) | 12 | 🟠 High | |
| GAP-08 | A.5.17 | Contractor access key 215 days old | [IAM-04](../02-evidence-collection/example-output/run_20261023T194112Z/IAM-04.json) | 12 | 🟠 High | |
| GAP-09 | A.5.24 | Incident response plan never approved or tested | IR-Plan-v0.3 | 12 | 🟠 High | |
| GAP-10 | A.5.17 | Password policy below baseline | [IAM-01](../02-evidence-collection/example-output/run_20261023T194112Z/IAM-01.json) | 9 | 🟡 Medium | |
| GAP-11 | A.5.18 | No periodic access reviews | Interview | 9 | 🟡 Medium | |
| GAP-12 | A.5.19 | Suppliers processing patient data never assessed | Supplier list | 9 | 🟡 Medium | |

Remediation actions, owners and effort for each gap are in [`gap-register.csv`](gap-register.csv).

## 5. Remediation roadmap

Sequenced by risk first, then by what certification needs and when.

**Days 0–30: close the breach paths and start the ISMS core**
- Enforce MFA for all console users; rotate or remove the contractor key (GAP-01, GAP-08, GAP-10)
- Remove public SSH; switch to SSM Session Manager (GAP-03)
- Enable GuardDuty and a multi-region, validated CloudTrail (GAP-06, GAP-07)
- Approve a risk methodology and build the first risk register (GAP-02)

**Days 31–60: build what the auditor will ask for first**
- Produce the Statement of Applicability from the risk treatment plan (GAP-04)
- Approve the IR plan and run a tabletop exercise (GAP-09)
- First quarterly access review (GAP-11)

**Days 61–90: prove the ISMS operates**
- Supplier tiering and assessments for critical suppliers (GAP-12)
- Complete a full internal audit cycle and management review (GAP-05)
- Re-run the evidence collector: target 9 of 9 checks passing

## 6. Limitations

- Technical testing covered one account and one region. Other accounts or regions may have additional gaps.
- Automated checks confirm configuration, not that people act on alerts. Operating effectiveness needs testing over a period (typically 3 months) before Stage 2.
- Interviews and documents were simulated, so ISMS findings illustrate method rather than describe a real company.

## Why I built it this way

**The deliverable is a decision, not a list.** A list of 12 gaps doesn't tell leadership what to do on Monday. Splitting *security risk* from *certification readiness* does, because the two point to different owners and different deadlines.

**Every finding traces to evidence.** Technical findings link to the exact JSON file the collector produced. If a finding is challenged, the answer is "re-run the script", not "trust me".

**Prioritisation is explicit and repeatable.** Likelihood × impact is simple on purpose: anyone can see why GAP-01 outranks GAP-10, and argue with a specific number instead of with the conclusion.
