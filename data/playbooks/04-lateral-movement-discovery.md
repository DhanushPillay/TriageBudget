# Lateral Movement and Discovery

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** LateralMovement, Discovery, Execution
**Role:** tier-2 analyst

## Summary

Use this playbook when one identity or host touches several systems, runs
discovery commands, or authenticates to remote services in a short window.
The key question is whether the activity is administrative automation or an
attacker expanding access.

## Detection signals

Remote service creation, SMB or WinRM logons from a workstation, account
enumeration, network scanning, credential dumping, and a sequence that starts
with one compromised host. A single remote logon can be routine.

## Triage questions

Is the source host a management server or a user workstation? Does the account
normally administer these targets? What discovery commands ran? Did the same
session create a service or copy a tool? Which hosts accepted the logon?

## Containment

Disable the source account or isolate the source host. Block the remote service
path at the network layer. Preserve authentication logs from every target
before resetting credentials.

## Eradication

Remove remote services, scheduled tasks, and copied tools. Reset credentials
used for lateral movement. Patch the exposed service or close the network path.

## Recovery

Re-enable accounts after credential rotation and scoped access review. Monitor
the source and target hosts for repeat remote logons.

## Escalation criteria

Escalate to incident response when a privileged account reaches multiple
targets, a service is created remotely, or discovery is followed by
exfiltration or impact. Involve the Windows or network team for containment.
