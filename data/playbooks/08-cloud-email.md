# Cloud and Email Compromise

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** InitialAccess, Exfiltration, CredentialAccess, CommandAndControl
**Role:** tier-1 analyst

## Summary

Use this playbook for mailbox rule changes, cloud token or app consent activity,
file-sharing changes, and suspicious cloud logons. Cloud incidents often leave
identity, audit, and mail evidence in separate systems.

## Detection signals

New inbox rule forwarding mail, OAuth consent to an unknown app, mass file
download, external sharing change, token use from a new location, and audit
events from an unfamiliar user agent.

## Triage questions

Which cloud service and account are involved? Was a new app or token created?
Did mail forwarding or external sharing change? What data was accessed or
downloaded? Is the source address expected? Are other users affected?

## Containment

Revoke sessions and tokens. Remove malicious mail rules and external sharing.
Disable the account if privileged data was accessed. Block the app or source
address at the identity provider.

## Eradication

Remove the OAuth grant, forwarding rule, and any added recovery method. Review
audit logs for persistence and repeat access. Reset the credential.

## Recovery

Re-enable the account with MFA and a fresh credential. Monitor mailbox and
cloud audit logs for repeat rule, token, or sharing changes.

## Escalation criteria

Escalate when privileged data was downloaded, an OAuth grant remains active,
mail forwarding reached an external address, or multiple accounts used the same
app or source.
