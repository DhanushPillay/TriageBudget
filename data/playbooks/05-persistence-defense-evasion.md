# Persistence and Defense Evasion

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** Persistence, DefenseEvasion, PrivilegeEscalation
**Role:** tier-2 analyst

## Summary

Use this playbook for autoruns, scheduled tasks, services, account creation,
security-tool tampering, or log clearing. Persistence changes are often
legitimate software behavior, so tie the change to a user action and a parent
process.

## Detection signals

New run key or startup folder entry, service creation from a user-writable
path, scheduled task with an encoded command, added local admin, disabled
security agent, and event log clearing. A signed installer can create similar
entries.

## Triage questions

What process created the persistence? Was the parent a known installer? Does
the entry point to a signed binary? Is the account change approved? Are there
matching execution or network alerts?

## Containment

Remove the persistence entry and isolate the host if the parent process is
unknown. Preserve the entry, command line, and signer before deletion. Disable
unauthorized accounts.

## Eradication

Delete the autorun, task, service, or account. Restore security-tool settings.
Scan for the payload that created the entry and check peer hosts for the same
artifact.

## Recovery

Reboot and verify the entry does not return. Monitor for recreation of the
same task, service, or account.

## Escalation criteria

Escalate when a security control was disabled, a privileged account was
created, or persistence is tied to malware execution. Involve platform owners
before removing a service that may be shared.
