# Contributing to altiward-siem

Thanks for helping. New detections, fixes to existing ones and better descriptions are all
welcome. For a new detection, open an issue first describing what it should catch, so we can
agree it belongs here. The organisation's
[general guide](https://github.com/Altiward/.github/blob/main/CONTRIBUTING.md) covers the
rest of how we work.

## Add or change a detection

A detection is usually a pair: a Sentinel rule and a Splunk search for the same thing.

**Sentinel analytics rule:** a YAML file in `sentinel/analytics-rules/`, in the schema of
Microsoft's [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository for scheduled
rules, plus `tags`:

- `id`: a new lowercase GUID (`uuidgen | tr A-Z a-z`). Never reuse or change one: Sentinel
  updates the rule with that ID.
- `name`: starts with `Altiward: `.
- `query`: reads `AltiwardOCSF_CL`. Use its columns where they fit (`ClassUid`,
  `ActivityId`, `SeverityId`, `DeviceSerial`, `UserName`, `Message`) and `Ocsf.*` for the
  rest of the OCSF record.
- `entityMappings`: map columns the query returns, usually Host from `DeviceSerial` and
  Account from `UserName`.
- `tags`: `altiward`, or `altiward` and `forwarder` if it also works on altiward-forwarder's
  records.
- `version`: raise it when you change the rule.

Only a subset of YAML is read: block mappings and lists, `|` blocks and plain or quoted
values. Quote a value that holds `: ` or ` #`.

**Hunting query:** a `.kql` file in `sentinel/hunting/`. Start it with `//` comment lines
saying what it finds, including a `// Tags: altiward` line.

**Splunk search:** a stanza in `splunk/savedsearches.conf` named `Altiward - <title>`, with
a `# Tags: altiward` line just above it, and the same search text in
`splunk/searches/<title in lowercase, with dashes>.spl`. Copy the settings from a similar
stanza: alerts have the `alert.*` and `counttype` settings, reports don't. Leave
`enableSched = 0`, so installing the file starts nothing.

Then run the checks and rebuild the ARM template:

```sh
scripts/build-arm.sh
make lint test check
```

## What the checks look at

`make check` (`go run ./tools/rulecheck check`) fails when:

- a rule has a missing, unknown or out-of-range key: a severity, tactic, entity type or
  duration Sentinel wouldn't accept, or an ID another rule has;
- a field a rule, hunting query or search names isn't in any fixture record it could
  match. It goes by the `ClassUid`/`class_uid` and `finding_info.analytic.name` the query
  filters on, separately for each tag: a `forwarder` rule must work on the forwarder's
  records;
- a saved search's text differs from its `.spl` file;
- `sentinel/azuredeploy.json` isn't what `scripts/build-arm.sh` makes.

`make test` runs the checker's own tests, and parses each rule with Ruby's YAML parser too
when Ruby is installed, to make sure the subset parser reads them the same way.

## Fixtures

`fixtures/altiward/` holds the Altiward server's OCSF output for its sample events
(`integrations/ocsf-examples` in the Altiward repository), and `fixtures/forwarder/` the
forwarder's (`testdata/ocsf`). They're copies: refresh them with

```sh
scripts/sync-fixtures.sh ../altiward ../altiward-forwarder
```

If your detection needs a field no fixture has, add an example to the project that produces
it first (in Altiward, `extraExamples` in `backend/internal/ocsf/golden_test.go`), then sync.

## Sign off your commits (DCO)

Add a sign-off to every commit, as the [Developer Certificate of
Origin](https://developercertificate.org) asks:

```sh
git commit -s -m "Add a rule for …"
```

We don't merge pull requests with commits that aren't signed off.

## Security

Please don't report a vulnerability in an issue. See the
[security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md).
