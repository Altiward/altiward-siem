# Changelog

Detections, hunting queries and saved searches, released as `vX.Y.Z`. Each release's section
is its notes on GitHub Releases. A release needs its section dated (`## X.Y.Z - YYYY-MM-DD`)
with a `### Changes` heading; `scripts/release-notes.sh` checks.

Versions: a new rule, search or field is a minor release, a fix is a patch, and a removed or
renamed rule or search is a breaking change, called out under `### Breaking changes`. Say for
each new or changed detection whose events it needs: Altiward, or both Altiward and
altiward-forwarder.

## 0.4.0 - unreleased

### Changes

- A hunting query for the use of permanent admin accounts, for Sentinel and Splunk: each
  sign-in at the Mac (at the login window, in Terminal or over SSH), each authorisation prompt
  approved and each screen sharing connection as an account that is always an administrator,
  over the last 30 days. sudo, su and SSH file copies or one-off commands are not recorded
  until Apple grants the Endpoint Security entitlement. It lists the
  Mac, the account, how it was used, whose session it was and when it started and ended. It
  is for review, not an alert. Needs Altiward server 0.4.0 and agent 0.3.0.
- The console sign-ins hunting query for Sentinel now counts only sign-ins to the Altiward
  console, as the Splunk search already did. Before, it would also list Mac sign-ins from the
  new permanent admin use records.

## 0.3.0 - 2026-10-24

### Changes

- The out-of-band detections keep alerting when Altiward server 0.3.0 closes a finding
  because the rights were removed: by Altiward's automatic removal, a revoke from the
  console, or by hand (status "Rights removed"). Such a finding alerts once, in the hour it
  was created. An explanation (the account made a permanent admin, or a Privileges grant)
  still closes it without an alert. On older servers' events the detections work as before.
  Needs Altiward's events.

## 0.2.0 - 2026-10-23

### Changes

- A detection that works with either project's events: one user's total admin time in a UTC
  day over a limit you set, 120 minutes by default. Set it to SAP Privileges' AdminBudget to
  report the same limit from your SIEM, for Macs on Privileges 2.6 and earlier too, without a
  clock change resetting it. altiward-forwarder's elevations count up to their expiry at most.
- With Altiward server 0.2.0 and agent 0.1.1, the tamper detections also alert on each attempt
  SAP Privileges' system extension blocked on itself (`altiward.tamper.privileges_blocked`,
  High), and the out-of-band detections close a finding when a Privileges grant replaces it.
  Neither needed a rule change; the example records are updated. Needs Altiward's events.
- The checks read Sentinel queries that start with `let` statements, and Splunk searches that
  make fields with `eval` or name fields in single quotes.

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
