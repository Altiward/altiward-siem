# Changelog

Detections, hunting queries and saved searches, released as `vX.Y.Z`. Each release's section
is its notes on GitHub Releases. A release needs its section dated (`## X.Y.Z - YYYY-MM-DD`)
with a `### Changes` heading; `scripts/release-notes.sh` checks.

Versions: a new rule, search or field is a minor release, a fix is a patch, and a removed or
renamed rule or search is a breaking change, called out under `### Breaking changes`. Say for
each new or changed detection whose events it needs: Altiward, or both Altiward and
altiward-forwarder.

## 0.1.0 - 2026-10-20

### Changes

- First release: Sentinel analytics rules and hunting queries, and Splunk saved searches, for
  the OCSF records the Altiward server and altiward-forwarder send. The Deploy to Azure button
  creates every analytics rule at once.
- Detections that need the Altiward server's events:
  - Admin rights SAP Privileges didn't grant, still unexplained.
  - Admin rights that outlived their expiry.
  - A tamper check failing on a Mac.
  - Persistence that appeared while someone was admin.
  - A local account that appeared while someone was admin.
  - A Mac that stopped checking in.
  - A grant or revoke the Mac's admin group contradicts.
  - The console's break-glass token used.
- A detection that works with either project's events: more than 10 elevations by one user in
  7 days.
- Hunting queries and reports: elevations with reason, expiry and who reported them (either
  project); console actions, and console sign-ins and sign-outs (Altiward).
