# Initial Access and Phishing

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** InitialAccess, Collection
**Role:** tier-1 analyst

## Summary

Use this playbook for suspicious mail, malicious links, attachment delivery,
or a first-stage payload that may open a broader intrusion. The goal is to
decide whether the message reached a user and whether execution occurred.

## Detection signals

Sender mismatch, newly registered domain, link redirect, attachment with a
script or archive, mail rule creation, and a click or execution event close to
delivery. A delivered message without a click is not the same as execution.

## Triage questions

Did the message reach the inbox or quarantine? Was the link opened? Was the
attachment executed? Which user and device are affected? Did the message go
to other recipients? Is the sender domain used elsewhere in the tenant?

## Containment

Quarantine the message and remove it from mailboxes. Block the sender, link,
and attachment hash. Isolate the device if execution is confirmed or strongly
suspected.

## Eradication

Remove dropped files, scheduled tasks, and mail rules. Reset the user session
if credentials were entered on a lookalike page. Search for the same message
across the tenant.

## Recovery

Restore the mailbox and device after cleaning and verification. Keep the
sender and indicator blocks until the campaign is understood.

## Escalation criteria

Escalate when execution is confirmed, credentials were submitted, the message
reached multiple users, or a mail rule or OAuth grant was created.
