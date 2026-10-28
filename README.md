# altiward-siem

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15965/badge)](https://www.bestpractices.dev/projects/15965)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Altiward/altiward-siem/badge)](https://scorecard.dev/viewer/?uri=github.com/Altiward/altiward-siem)

Detections, hunting queries and saved searches for [Altiward](https://github.com/Altiward/altiward)
and [altiward-forwarder](https://github.com/Altiward/altiward-forwarder) events in Microsoft
Sentinel and Splunk.

Both projects send your SIEM the same OCSF records: the Altiward server for everything its
agent sees, and the forwarder for SAP Privileges' own grant and revoke reports. The content
here reads those records in Sentinel's `AltiwardOCSF_CL` table and Splunk's `altiward:ocsf`
sourcetype, the way the Altiward setup creates them. CI checks every field a rule or search
names against example records from both projects.

**Status:** see the [latest release](https://github.com/Altiward/altiward-siem/releases/latest)
for the published version and [CHANGELOG.md](CHANGELOG.md) for released and upcoming
changes. Pin a release, and watch the repository's releases to
hear when rules are added or changed: each release's notes, also in
[CHANGELOG.md](CHANGELOG.md), say what changed and whose events it needs.

## What's here

Each detection says whose events it needs. **Altiward** means the Altiward server. **Both**
means it also works with altiward-forwarder's records, which are grants and revokes only
(OCSF User Access Management, `class_uid` 3005).

| Detection | Needs | Sentinel | Splunk |
| --- | --- | --- | --- |
| Admin rights SAP Privileges didn't grant, still unexplained | Altiward | [rule](sentinel/analytics-rules/admin-out-of-band.yaml) | [alert](splunk/searches/admin-rights-not-granted-by-sap-privileges.spl) |
| Admin rights that outlived their expiry | Altiward | [rule](sentinel/analytics-rules/rights-after-expiry.yaml) | [alert](splunk/searches/admin-rights-after-expiry.spl) |
| A tamper check failing on a Mac | Altiward | [rule](sentinel/analytics-rules/tamper.yaml) | [alert](splunk/searches/tamper-checks-failing.spl) |
| A SAP Privileges grant claim the agent refused or Privileges' log didn't confirm | Altiward | [rule](sentinel/analytics-rules/grant-claim.yaml) | [alert](splunk/searches/grant-claims-refused-or-not-confirmed.spl) |
| A Mac account's Platform SSO link that may now name someone else | Altiward | [rule](sentinel/analytics-rules/platform-sso-link-changed.yaml) | [alert](splunk/searches/platform-sso-link-changed.spl) |
| A device key replaced without approval | Altiward | [rule](sentinel/analytics-rules/device-key-replaced-without-approval.yaml) | [alert](splunk/searches/device-key-replaced-without-approval.spl) |
| A device key waiting for approval | Altiward | [rule](sentinel/analytics-rules/device-key-waiting-for-approval.yaml) | [alert](splunk/searches/device-key-waiting-for-approval.spl) |
| A device key that the Mac had already replaced by rotation, used again | Altiward | [rule](sentinel/analytics-rules/rotated-device-key-used.yaml) | [alert](splunk/searches/rotated-device-key-used.spl) |
| Bursts of new Macs enrolled with one token | Altiward | [hunting](sentinel/hunting/enrolment-bursts.kql) | [report](splunk/searches/enrolment-bursts.spl) |
| Persistence that appeared while someone was admin | Altiward | [rule](sentinel/analytics-rules/persistence-while-admin.yaml) | [alert](splunk/searches/persistence-while-admin.spl) |
| A local account that appeared while someone was admin | Altiward | [rule](sentinel/analytics-rules/account-created.yaml) | [alert](splunk/searches/local-account-created-while-admin.spl) |
| A Mac that stopped checking in | Altiward | [rule](sentinel/analytics-rules/agent-silent.yaml) | [alert](splunk/searches/macs-that-stopped-checking-in.spl) |
| A grant or revoke the Mac's admin group contradicts | Altiward | [rule](sentinel/analytics-rules/contradicted-claim.yaml) | [alert](splunk/searches/contradicted-grants-and-revokes.spl) |
| The console's break-glass token used | Altiward | [rule](sentinel/analytics-rules/break-glass-token.yaml) | [alert](splunk/searches/break-glass-token-use.spl) |
| More than 10 elevations by one user in 7 days | Both | [rule](sentinel/analytics-rules/frequent-elevations.yaml) | [alert](splunk/searches/frequent-elevations.spl) |
| One user's admin time in a UTC day over a limit you set (120 minutes by default) | Both | [rule](sentinel/analytics-rules/admin-time-per-day.yaml) | [alert](splunk/searches/admin-time-per-user-per-day.spl) |
| Elevations, with reason, expiry and who reported them | Both | [hunting](sentinel/hunting/elevations.kql) | [report](splunk/searches/elevations.spl) |
| Console actions: revokes, enrollment approvals, settings changes | Altiward | [hunting](sentinel/hunting/console-actions.kql) | [report](splunk/searches/console-actions.spl) |
| Console sign-ins and sign-outs | Altiward | [hunting](sentinel/hunting/console-sign-ins.kql) | [report](splunk/searches/console-sign-ins.spl) |
| Use of permanent admin accounts: sign-ins, authorisation prompts and screen sharing | Altiward | [hunting](sentinel/hunting/permanent-admin-use.kql) | [report](splunk/searches/permanent-admin-use.spl) |

Sentinel rules run every hour over the last hour (grant claims, Platform SSO link changes and
device keys: every 15 minutes; the elevation count: daily over 7 days; admin time per day:
daily, for the last complete UTC day).
Rules about findings that can be resolved (unexplained admin rights, tamper checks, silent
Macs) alert only on findings still open at the end of that hour. One exception: an
unexplained-admin-rights finding closed because the rights were removed still alerts once.

On a Mac registered for Platform SSO, Altiward takes each person's UPN from their Mac
account's Platform SSO link. A link that may now name someone else is High, with the Mac
account and the UPNs before and after: check with the account's owner, and in your identity
provider, that the new link is theirs. Other links added or removed, which mostly record
people registering for Platform SSO, don't alert.

In the device-key detections, a pending key is Medium and needs checking against the Mac's
last check-in, the reported hardware UUID comparison and its owner's expectations. With
**Approve every new Mac** on, every new Mac raises one too. A key replaced with approval
off is High. Enrolment bursts count distinct claimed serials per tenant and token over an
hour, with a tunable threshold of 10. Normal rollouts can produce bursts too; compare independent
inventory, because a shared enrolment token can enrol invented serials.

The rotated-device-key detection is High. It means two
copies of one Mac's device key were used. When RevokedDeviceId is set, the server has
revoked the lineage's key and the Mac enrols again by itself. When it is empty, nothing was
revoked: the key was replaced more than 30 days ago, or this key already caused a
revocation. A copy carries the Mac's serial number and hardware UUID, so they don't tell
its key from the Mac's. Run `altiward-agent status` on the Mac through your MDM, approve
only the pending key whose fingerprint in Enrollments matches the `key fingerprint` it
prints, and reject the others. When RevokedDeviceId is empty and the pending key is the
Mac's, the active key, if there is one, isn't the Mac's: revoke it, then approve the Mac's
key. Look for where the copy came from: backups, disk images and Migration Assistant. A Mac restored from a backup older than its last rotation also raises it, and
its fresh key is genuine.

Altiward-forwarder's webhook events name the Mac by `device.uid` only, so `DeviceSerial`
(Sentinel) is empty for them and Splunk's `host` is the hardware UUID. Its on-Mac hook
reports the serial number too.

## Microsoft Sentinel

First set up the `AltiwardOCSF_CL` table as
[Altiward's Sentinel guide](https://github.com/Altiward/altiward/tree/main/integrations/sentinel)
describes (altiward-forwarder uses the same table). Rules can't be created before it exists.

### All analytics rules at once

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAltiward%2Faltiward-siem%2Fv1.0.0%2Fsentinel%2Fazuredeploy.json)

Choose the resource group of your Sentinel workspace and enter the workspace's name. It
creates the rules turned on, with one alert per result row. The button deploys
[`sentinel/azuredeploy.json`](sentinel/azuredeploy.json) from the `v1.0.0` release.

### Verify downloaded release files

Releases include `SHA256SUMS` and its keyless signature bundle, `SHA256SUMS.sigstore.json`.
To verify a release, install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
and download all four assets from the chosen release into a new directory. For 1.0.0:

```sh
tag=v1.0.0
mkdir "altiward-siem-$tag"
cd "altiward-siem-$tag"
for file in azuredeploy.json RELEASE_NOTES.md SHA256SUMS SHA256SUMS.sigstore.json; do
  curl --fail --location --output "$file" \
    "https://github.com/Altiward/altiward-siem/releases/download/$tag/$file"
done
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Altiward/altiward-siem/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
```

On macOS, replace the final command with `shasum -a 256 -c SHA256SUMS`. Continue only if
both verification commands succeed. The signature binds the checksums to this repository's
release workflow, the chosen tag and the GitHub Actions OIDC issuer. Checksums alone detect
changed files but do not establish who published them. Use the verified `azuredeploy.json`
when deploying a downloaded template. The Deploy to Azure button fetches its pinned source
file directly and does not perform these consumer verification commands.

### One rule at a time

In Sentinel, Analytics, create a scheduled query rule from the rule's YAML, or import the
YAML with your detection-as-code tooling. The files follow the schema of Microsoft's
[Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository, plus a `tags` key
saying whose events the rule needs.

### Hunting queries

Paste a `.kql` file from [`sentinel/hunting/`](sentinel/hunting/) into Logs, or save it as a
hunting query.

## Splunk

[`splunk/savedsearches.conf`](splunk/savedsearches.conf) has every search as a saved search:
alerts that run hourly (grant claims, Platform SSO link changes and device keys: every 15
minutes; the elevation count and admin time per day: daily) and reports. Copy
it to `$SPLUNK_HOME/etc/apps/<your app>/local/savedsearches.conf` and restart Splunk. The
searches are off until you enable them in Settings, Searches, reports, and alerts, where you
also add the alert action you want (email, a webhook, your SOAR).

To run one by hand, paste its `.spl` file from [`splunk/searches/`](splunk/searches/) into
Search.

The searches expect events with sourcetype `altiward:ocsf`, which both projects' HTTP Event
Collector exports use. See [Altiward's Splunk guide](https://github.com/Altiward/altiward/tree/main/integrations/splunk)
for the setup and the dashboard.

## The events

The records are OCSF 1.9.0. The Altiward repository documents each event, and its OCSF
output for sample events is in
[`integrations/ocsf-examples`](https://github.com/Altiward/altiward/tree/main/integrations/ocsf-examples).
Copies of those, and of the forwarder's records, are in [`fixtures/`](fixtures/): the checks
read them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to add or change a detection. Report security problems
privately, as the [security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md)
describes.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SAP and SAP Privileges are
trademarks of SAP SE; this project isn't affiliated with or endorsed by SAP.
