# Command and Control and Exfiltration

**Source:** synthetic tabletop guidance for TriageBudget
**Effective:** 2026-01-15
**Categories:** CommandAndControl, Exfiltration, Collection
**Role:** tier-2 analyst

## Summary

Use this playbook for beaconing, suspicious outbound connections, large uploads,
or collection activity that may precede data loss. Confirm the destination and
the data volume before calling it exfiltration.

## Detection signals

Periodic connections to a new domain, uncommon port or protocol, encoded DNS,
cloud storage upload, large transfer from a server, and staging archives in a
temp path. Backup and sync clients can produce similar traffic.

## Triage questions

Is the destination approved for this host? What data left and how much? Is the
connection periodic? Which process owns the connection? Is there a matching
endpoint or identity alert? Are other hosts contacting the same destination?

## Containment

Block the destination at the proxy or DNS layer. Isolate the source host if
beaconing is confirmed. Preserve proxy, DNS, and flow logs before rotating
credentials.

## Eradication

Remove the beacon and the process that launched it. Remove staged archives and
scheduled upload jobs. Rotate credentials or tokens exposed to the host.

## Recovery

Restore the host after cleaning and confirm the destination is blocked. Monitor
for reconnection attempts and for the same destination from peer hosts.

## Escalation criteria

Escalate to incident response and data protection when sensitive data left the
environment, a cloud storage destination received uploads, or multiple hosts
show the same beacon.
