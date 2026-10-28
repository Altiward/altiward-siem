package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodRule = `id: 8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d
name: "Altiward: persistence while admin"
description: |
  Persistence that appeared while someone was admin.
severity: High
requiredDataConnectors: []
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1543.004
  - T1098.004
query: |
  AltiwardOCSF_CL
  | where ClassUid == 2004 and tostring(Ocsf.finding_info.analytic.name) == "altiward.persistence_detected"
  | project TimeGenerated, DeviceSerial, UserName, Message
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceSerial
tags:
  - altiward
version: 1.0.0
kind: Scheduled
`

const goodSearch = `sourcetype="altiward:ocsf" class_uid=3005 activity_id=1 status_id=1 earliest=-7d
| stats count by user.name | where count > 10`

const goodConf = `# Tags: altiward, forwarder
[Altiward - Frequent elevations]
description = More than 10 elevations per user in 7 days.
search = sourcetype="altiward:ocsf" class_uid=3005 activity_id=1 status_id=1 earliest=-7d \
| stats count by user.name | where count > 10
dispatch.earliest_time = -7d@d
dispatch.latest_time = @d
cron_schedule = 0 6 * * *
enableSched = 0
`

const goodHunting = `// Console actions: who did what.
// Tags: altiward
AltiwardOCSF_CL
| where ClassUid == 6003
| project TimeGenerated, UserName, Action = tostring(Ocsf.api.operation), Message
`

const altiwardFixtures = `[
  {"class_uid": 2004, "time": 1, "message": "m", "device": {"hw_info": {"serial_number": "C02"}}, "user": {"name": "jdoe"},
   "finding_info": {"analytic": {"name": "altiward.persistence_detected"}}},
  {"class_uid": 3005, "activity_id": 1, "status_id": 1, "time": 1, "message": "m", "user": {"name": "jdoe"}},
  {"class_uid": 6003, "time": 1, "message": "m", "actor": {"user": {"name": "a@x"}}, "api": {"operation": "revoke_device"}}
]`

const forwarderFixtures = `[{"class_uid": 3005, "activity_id": 1, "status_id": 1, "time": 1, "message": "m", "user": {"name": "jdoe"}}]`

// testRepo writes a repo that passes, with files overriding or adding to it ("" deletes).
func testRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		"fixtures/altiward/examples.json":           altiwardFixtures,
		"fixtures/forwarder/examples.json":          forwarderFixtures,
		"sentinel/analytics-rules/persistence.yaml": goodRule,
		"sentinel/hunting/console-actions.kql":      goodHunting,
		"splunk/savedsearches.conf":                 goodConf,
		"splunk/searches/frequent-elevations.spl":   goodSearch + "\n",
	}
	for k, v := range files {
		if v == "" {
			delete(all, k)
		} else {
			all[k] = v
		}
	}
	for name, content := range all {
		path := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := files["sentinel/azuredeploy.json"]; !ok {
		rules, errs := loadRules(root)
		if len(errs) > 0 {
			return root // the test is about a broken rule
		}
		b, err := buildARM(rules)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(root, "sentinel/azuredeploy.json"), b, 0o644)
	}
	return root
}

func wantProblem(t *testing.T, root string, mentions ...string) {
	t.Helper()
	problems := check(root)
	all := ""
	for _, p := range problems {
		all += p.Error() + "\n"
	}
	for _, m := range mentions {
		if !strings.Contains(all, m) {
			t.Errorf("no problem mentions %q; got:\n%s", m, all)
		}
	}
}

func TestCheckPassesAGoodRepo(t *testing.T) {
	if problems := check(testRepo(t, nil)); len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
}

func TestCheckFindsAFieldNoFixtureHas(t *testing.T) {
	rule := strings.Replace(goodRule, "| project TimeGenerated,", "| project Reason = tostring(Ocsf.unmapped.altiward.reason), TimeGenerated,", 1)
	wantProblem(t, testRepo(t, map[string]string{"sentinel/analytics-rules/persistence.yaml": rule}),
		"persistence.yaml", "Ocsf.unmapped.altiward.reason")

	// A field that exists, but only in records the query can't match, doesn't count.
	hunting := strings.Replace(goodHunting, "tostring(Ocsf.api.operation)", "tostring(Ocsf.finding_info.analytic.name)", 1)
	wantProblem(t, testRepo(t, map[string]string{"sentinel/hunting/console-actions.kql": hunting}), "console-actions.kql", "Ocsf.finding_info.analytic.name")

	search := strings.Replace(goodSearch, "by user.name", "by user.email_addr", 1)
	conf := strings.Replace(goodConf, "by user.name", "by user.email_addr", 1)
	wantProblem(t, testRepo(t, map[string]string{"splunk/searches/frequent-elevations.spl": search + "\n", "splunk/savedsearches.conf": conf}),
		"Frequent elevations", "user.email_addr")
}

// A rule tagged forwarder must work on the forwarder's records, which are 3005 only.
func TestCheckForwarderTagNeedsForwarderRecords(t *testing.T) {
	rule := strings.Replace(goodRule, "  - altiward\n", "  - altiward\n  - forwarder\n", 1)
	wantProblem(t, testRepo(t, map[string]string{"sentinel/analytics-rules/persistence.yaml": rule}), "persistence.yaml", "no forwarder fixture")
}

func TestCheckAnalyticNeedsAFixture(t *testing.T) {
	rule := strings.Replace(goodRule, "altiward.persistence_detected", "altiward.something_new", 1)
	wantProblem(t, testRepo(t, map[string]string{"sentinel/analytics-rules/persistence.yaml": rule}), "no altiward fixture", "altiward.something_new")
}

func TestCheckRuleKeys(t *testing.T) {
	for name, c := range map[string]struct{ from, to, mentions string }{
		"missing key":     {"severity: High\n", "", "severity"},
		"unknown key":     {"kind: Scheduled\n", "kind: Scheduled\nenabled: true\n", "enabled"},
		"severity":        {"severity: High", "severity: Severe", "severity"},
		"id":              {"id: 8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d", "id: rule-1", "id"},
		"tactic":          {"  - Persistence\n", "  - Lingering\n", "Lingering"},
		"technique":       {"  - T1543.004\n", "  - 1543\n", "1543"},
		"operator":        {"triggerOperator: gt", "triggerOperator: more", "triggerOperator"},
		"frequency":       {"queryFrequency: 1h", "queryFrequency: hourly", "queryFrequency"},
		"period too long": {"queryPeriod: 1h", "queryPeriod: 15d", "queryPeriod"},
		"period short":    {"queryPeriod: 1h", "queryPeriod: 30m", "queryPeriod"},
		"tag":             {"  - altiward\n", "  - splunk\n", "splunk"},
		"kind":            {"kind: Scheduled", "kind: NRT", "kind"},
		"version":         {"version: 1.0.0", "version: 1", "version"},
		"table":           {"  AltiwardOCSF_CL\n", "  SecurityEvent\n", "AltiwardOCSF_CL"},
		"entity column":   {"columnName: DeviceSerial", "columnName: Computer", "Computer"},
		"entity type":     {"entityType: Host", "entityType: Laptop", "Laptop"},
		"severity column": {"kind: Scheduled\n", "alertDetailsOverride:\n  alertSeverityColumnName: Level\nkind: Scheduled\n", "Level"},
		"other override":  {"kind: Scheduled\n", "alertDetailsOverride:\n  alertDisplayNameFormat: x\nkind: Scheduled\n", "alertSeverityColumnName"},
	} {
		rule := strings.Replace(goodRule, c.from, c.to, 1)
		if rule == goodRule {
			t.Fatalf("%s: the test's replacement didn't apply", name)
		}
		t.Run(name, func(t *testing.T) {
			wantProblem(t, testRepo(t, map[string]string{"sentinel/analytics-rules/persistence.yaml": rule}), "persistence.yaml", c.mentions)
		})
	}
	wantProblem(t, testRepo(t, map[string]string{"sentinel/analytics-rules/copy.yaml": goodRule}), "copy.yaml", "8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d")
}

func TestCheckHuntingNeedsTags(t *testing.T) {
	wantProblem(t, testRepo(t, map[string]string{"sentinel/hunting/console-actions.kql": strings.Replace(goodHunting, "// Tags: altiward\n", "", 1)}),
		"console-actions.kql", "Tags")
}

func TestCheckSplunkSearchesMatchTheirFiles(t *testing.T) {
	wantProblem(t, testRepo(t, map[string]string{"splunk/searches/frequent-elevations.spl": strings.Replace(goodSearch, "> 10", "> 20", 1) + "\n"}),
		"Frequent elevations", "frequent-elevations.spl")
	wantProblem(t, testRepo(t, map[string]string{"splunk/searches/frequent-elevations.spl": ""}), "frequent-elevations.spl")
	wantProblem(t, testRepo(t, map[string]string{"splunk/searches/orphan.spl": goodSearch}), "orphan.spl")
	wantProblem(t, testRepo(t, map[string]string{"splunk/savedsearches.conf": strings.Replace(goodConf, "# Tags: altiward, forwarder\n", "", 1)}),
		"Frequent elevations", "Tags")
	wantProblem(t, testRepo(t, map[string]string{"splunk/savedsearches.conf": strings.Replace(goodConf, "cron_schedule = 0 6 * * *\n", "", 1)}),
		"Frequent elevations", "cron_schedule")
	wantProblem(t, testRepo(t, map[string]string{"splunk/savedsearches.conf": strings.Replace(goodConf, "[Altiward - ", "[", 1)}),
		"Altiward - ")
}

func TestCheckARMIsCurrent(t *testing.T) {
	wantProblem(t, testRepo(t, map[string]string{"sentinel/azuredeploy.json": "{}\n"}), "azuredeploy.json", "scripts/build-arm.sh")
}

func TestCheckNeedsFixtures(t *testing.T) {
	wantProblem(t, testRepo(t, map[string]string{"fixtures/forwarder/examples.json": ""}), "fixtures/forwarder")
	wantProblem(t, testRepo(t, map[string]string{"fixtures/altiward/bad.json": "{not json"}), "bad.json")
}

// TestRepository: this repository's own content passes.
func TestRepository(t *testing.T) {
	for _, p := range check("../..") {
		t.Error(p)
	}
}
