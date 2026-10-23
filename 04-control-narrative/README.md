# 04 · Control Narrative

**File:** [`A.8.15-logging.md`](A.8.15-logging.md)

## What I built

A full control narrative for ISO/IEC 27001:2022 **A.8.15 Logging**, written the way it would be handed to an auditor: the control statement, the risk it addresses, exactly how it is implemented, what evidence it produces, and the test of design and operating effectiveness I would run.

## Why this control

Logging is the control every other control depends on. Without trustworthy logs you can't prove MFA was enforced, investigate an incident or show that a change was approved. It is also the control Tausi currently fails ([GAP-06](../03-gap-assessment/README.md#4-findings)), so the narrative doubles as the engineering team's definition of "done".

## What I'd do next

Write narratives for A.8.5 (secure authentication) and A.5.18 (access rights). Together with A.8.15 they cover the identity-to-evidence chain an auditor follows first.
