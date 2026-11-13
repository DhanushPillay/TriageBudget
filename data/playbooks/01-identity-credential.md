# Identity and Credential Compromise

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** CredentialAccess, InitialAccess, PrivilegeEscalation
**Role:** tier-1 analyst

## Summary

Use this playbook when an incident shows logon anomalies, credential theft
signals, impossible travel, token replay, or repeated authentication failures
followed by a successful session. Separate noisy password spray from a session
that reached a privileged resource.

## Detection signals

Repeated failures from one address, a success after many failures, unfamiliar
device or location, token issuance without an interactive logon, and access to
privileged applications. A successful logon by itself is weak evidence.

## Triage questions

Was the successful session interactive or token-based? Did the account reach a
new resource? Is the source address expected for this user? Did the same
address target several accounts? Is there a matching endpoint or mailbox alert?

## Containment

Disable the account or revoke sessions when a privileged resource was reached.
Reset credentials after collecting session and authentication logs. Do not
disable a shared service account without identifying its owners first.

## Eradication

Remove persisted tokens, app consents, or added authentication methods. Review
mailbox rules and OAuth grants created near the incident window. Confirm the
source address is blocked at the identity provider.

## Recovery

Re-enable the account with a fresh credential and require reauthentication.
Monitor the account for seven days for repeat token or logon anomalies.

## Escalation criteria

Escalate to identity response when a privileged role, mailbox delegation, or
new OAuth grant is involved. Escalate to incident response if multiple accounts
show the same source or token pattern.
