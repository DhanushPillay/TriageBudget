# Incident Response and Escalation

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** SuspiciousActivity, Impact, Exfiltration, Ransomware
**Role:** incident commander

## Summary

Use this playbook when an incident is ambiguous, spans several categories, or
has a weak classifier score but high potential impact. The goal is to decide
what evidence is missing and who should own the next step.

## Detection signals

Conflicting signals, a high alert volume without a clear verdict, a sensitive
asset, an executive or admin account, a production outage, or a detection that
crosses queue boundaries. Uncertainty is a reason to collect evidence, not to
guess.

## Triage questions

What is the worst plausible outcome? Which evidence would confirm or rule it
out? Who owns the affected asset? Is the incident already contained? What is
the time sensitivity? Has a similar case been reviewed before?

## Containment

Choose the least destructive action that stops spread. Prefer session revoke,
network block, or host isolation over account deletion. Record the action and
the reason in the incident.

## Eradication

Assign an owner for each unresolved question. Collect the missing logs before
making irreversible changes. Close the loop on every containment action.

## Recovery

Define the exit criteria before restoring service. Confirm monitoring covers
the original signal and the containment path.

## Escalation criteria

Escalate to a human reviewer when confidence is low, evidence conflicts, the
asset is business-critical, or the decision would disable a shared account.
Escalate to incident command for ransomware, data loss, or multi-host spread.
