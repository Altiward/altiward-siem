package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

var (
	kqlToString = regexp.MustCompile(`(\w+)\s*=\s*tostring\(Ocsf((?:\.\w+)+)\)`)
	kqlSeverity = regexp.MustCompile(`(\w+)\s*=\s*iff\((\w+)\s*==\s*"([^"]*)",\s*"(\w+)",\s*"(\w+)"\)`)
)

// Two detections alert at the severity the Altiward server gives each record: a silence
// raised early because Intune still hears from the Mac (basis mdm_check_in) and a key
// enrolled with another device's Intune ID (mdm_check mismatch) are High, the rest Medium.
// Sentinel sets each alert's severity from a column (alertDetailsOverride); Splunk can't, so
// it has a High saved search beside the Medium one. This test runs both on every fixture
// the rule matches, on a silence from a server before 1.2.0 (no basis), and on the resume
// that closes an early silence, which every search must see so the finding closes.
func TestSeverityFollowsTheRecord(t *testing.T) {
	const root = "../.."
	fx, errs := loadFixtures(root)
	rules, ruleErrs := loadRules(root)
	if errs = append(errs, ruleErrs...); len(errs) > 0 {
		t.Fatal(errs)
	}
	b, err := os.ReadFile(filepath.Join(root, "splunk", "savedsearches.conf"))
	if err != nil {
		t.Fatal(err)
	}
	stanzas, problems := parseConf(string(b))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	searches := map[string]stanza{}
	for _, s := range stanzas {
		searches[s.Name] = s
	}
	byFile := map[string]rule{}
	for _, r := range rules {
		byFile[filepath.Base(r.File)] = r
	}
	fixture := func(name string) map[string]any {
		for _, f := range fx {
			if filepath.Base(f.File) == name {
				var r map[string]any
				b, _ := json.Marshal(f.Record)
				json.Unmarshal(b, &r)
				return r
			}
		}
		t.Fatalf("no fixture %s", name)
		return nil
	}
	detail := func(r map[string]any) map[string]any {
		return r["unmapped"].(map[string]any)["altiward"].(map[string]any)["detail"].(map[string]any)
	}

	// A silence from a server before 1.2.0, which sent no basis.
	oldSilence := fixture("agent-silent.json")
	delete(detail(oldSilence), "basis")
	delete(detail(oldSilence), "admin_members")
	// The resume that closes the early silence: Close, Informational, with no basis.
	resume := fixture("agent-silent-mdm.json")
	resume["activity_id"], resume["activity_name"] = 3.0, "Close"
	resume["severity_id"], resume["severity"] = 1.0, "Informational"
	resume["unmapped"].(map[string]any)["altiward"].(map[string]any)["detail"] = map[string]any{
		"state": "resumed", "last_seen_at": "2026-10-16T12:00:00Z", "silent_since": "2026-10-16T09:05:00Z",
	}

	for _, c := range []struct {
		rule     string
		searches []string
		forged   map[string]map[string]any
	}{
		{"agent-silent.yaml", []string{"Altiward - Macs that stopped checking in",
			"Altiward - Macs that stopped checking in while Intune hears from them"},
			map[string]map[string]any{"a silence from a server before 1.2.0": oldSilence, "the resume of an early silence": resume}},
		{"device-key-waiting-for-approval.yaml", []string{"Altiward - Device key waiting for approval",
			"Altiward - Device key waiting for approval with an Intune mismatch"}, nil},
	} {
		r, ok := byFile[c.rule]
		if !ok {
			t.Fatalf("no sentinel/analytics-rules/%s", c.rule)
		}
		col := r.AlertDetailsOverride["alertSeverityColumnName"]
		m := kqlSeverity.FindStringSubmatch(r.Query)
		if col == "" || m == nil || m[1] != col {
			t.Fatalf("%s: want alertSeverityColumnName set by %s = iff(Column == \"value\", \"High\", \"Medium\") in the query", c.rule, col)
		}
		paths := map[string]string{}
		for _, p := range kqlToString.FindAllStringSubmatch(r.Query, -1) {
			paths[p[1]] = p[2][1:]
		}
		if paths[m[2]] == "" {
			t.Fatalf("%s: %s isn't tostring(Ocsf...)", c.rule, m[2])
		}
		sentinelSeverity := func(rec map[string]any) string {
			if value(rec, paths[m[2]]) == m[3] {
				return m[4]
			}
			return m[5]
		}

		type record struct {
			name string
			r    map[string]any
		}
		var records []record
		for _, f := range fx {
			if kqlMatches(t, r.Query, f.Record) {
				records = append(records, record{filepath.ToSlash(f.File), f.Record})
			}
		}
		for name, rec := range c.forged {
			records = append(records, record{name, rec})
		}
		seen := map[string]int{}
		for _, rec := range records {
			want := value(rec.r, "severity")
			var got []string
			for _, name := range c.searches {
				s, ok := searches[name]
				if !ok {
					t.Fatalf("no saved search [%s]", name)
				}
				if splMatches(t, s.Keys["search"], rec.r) {
					got = append(got, name)
				}
			}
			if want == "Informational" {
				if len(got) != len(c.searches) {
					t.Errorf("Splunk, %s: a closing record reaches only %q, want every search, so the finding closes", rec.name, got)
				}
				continue
			}
			seen[want]++
			if s := sentinelSeverity(rec.r); s != want {
				t.Errorf("Sentinel %s, %s: alert severity %s, want the record's %s", c.rule, rec.name, s, want)
			}
			if len(got) != 1 {
				t.Errorf("Splunk, %s: matched by %q, want exactly one search", rec.name, got)
				continue
			}
			if level := searches[got[0]].Keys["alert.severity"]; level != strconv.Itoa(map[string]int{"High": 5, "Medium": 4}[want]) {
				t.Errorf("Splunk, %s: [%s] has alert.severity %s, want %s's", rec.name, got[0], level, want)
			}
		}
		if seen["High"] == 0 || seen["Medium"] == 0 {
			t.Errorf("%s: want High and Medium fixtures, found %v", c.rule, seen)
		}
	}
}
