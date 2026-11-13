# Ransomware and Impact

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** Ransomware, Impact
**Role:** incident commander

## Summary

Use this playbook when encryption, destructive commands, ransom notes, or
wide-scale service disruption appear. Treat confirmed encryption as an active
incident, not a queue item.

## Detection signals

Mass file rename or extension change, shadow-copy deletion, backup deletion,
ransom note creation, and a burst of access-denied errors. A single encrypted
file can be test activity.

## Triage questions

Which hosts or shares show encryption? Are backups reachable and intact? What
account or process is doing the encryption? Is the spread ongoing? Which
business services are affected? Is there a ransom note or leak-site reference?

## Containment

Isolate affected hosts and disable the involved account. Cut network paths
between affected and clean segments. Protect backups by removing write access.
Do not pay or contact the actor without incident-command approval.

## Eradication

Remove the encryptor and the initial access path. Rebuild hosts from trusted
images. Rotate credentials that were present on affected systems.

## Recovery

Restore from validated backups in a clean segment. Verify integrity before
reconnecting. Prioritize business-critical services and monitor for re-entry.

## Escalation criteria

Escalate immediately to incident command, leadership, legal, and communications.
Engage law enforcement according to organizational policy. Treat backup
deletion or hypervisor impact as critical.
