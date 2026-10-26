# Changelog

Detections, hunting queries and saved searches, released as `vX.Y.Z`. Each release's section
is its notes on GitHub Releases. A release needs its section dated (`## X.Y.Z - YYYY-MM-DD`)
with a `### Changes` heading; `scripts/release-notes.sh` checks.

Versions: a new rule, search or field is a minor release, a fix is a patch, and a removed or
renamed rule or search is a breaking change, called out under `### Breaking changes`. Say for
each new or changed detection whose events it needs: Altiward, or both Altiward and
altiward-forwarder.

## 0.9.0 - unreleased

### Changes

- Sentinel and Splunk alert on `agent.enrollment`: a device key replaced without approval
  at High, or waiting for approval at Medium, every 15 minutes. The result includes the
  token fingerprint, both device IDs, reported hardware UUID comparison and key storage.
  Check pending keys against the Mac's last check-in and its owner's expectations.
- A Sentinel hunting query and Splunk report find at least 10 distinct claimed serials
  enrolled by one token in an hour, per tenant. Tune the threshold for normal rollouts;
  check unexpected bursts against independent inventory for invented serials. Exact
  retries do not increase the count. Both additions need Altiward server 0.8.0.
- Console action reports select the Altiward console service, so enrolments are not
  presented as console actions.
- A detection for SAP Privileges grant claims, for Sentinel and Splunk: a claim from
  Privileges' hook that the Altiward agent refused, or accepted without Privileges' own log
  backing it (`altiward.tamper.grant_claim`). Someone who already holds admin rights can run
  the hook by hand to make them look granted, so it alerts at High, every 15 minutes, with the
  account, what was claimed (grant, renewal or give-back), the outcome and the reason. Needs
  Altiward server 0.5.0 and agent 0.4.0.
- "A tamper check is failing" leaves grant claims out, so they don't alert twice. Before, it
  alerted on them at Medium, at the end of the hour.

## 0.4.0 - 2026-10-24

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
