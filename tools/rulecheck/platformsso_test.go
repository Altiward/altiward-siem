package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Three rules share the agent's tamper findings: "a tamper check is failing" and the two with
// their own, sooner, High alert (grant claims and Platform SSO link changes). Each finding
// must reach exactly one of them, except a Platform SSO link added or removed
// (platform_sso_link), which mostly records registrations and reaches none. The checks only
// look at classes and analytic names, so this test reads the three filters and runs them on
// the fixtures, on a registration, and on a changed link whose check a Mac sent in capitals.
func TestTamperRulesSplitPlatformSSOLinks(t *testing.T) {
	const root = "../.."
	fx, errs := loadFixtures(root)
	rules, ruleErrs := loadRules(root)
	if errs = append(errs, ruleErrs...); len(errs) > 0 {
		t.Fatal(errs)
	}
	kql := map[string]string{}
	for _, r := range rules {
		kql[filepath.Base(r.File)] = r.Query
	}
	type detection struct{ name, kql, spl string }
	load := func(name, rule, search string) detection {
		if kql[rule] == "" {
			t.Fatalf("no sentinel/analytics-rules/%s", rule)
		}
		spl, err := os.ReadFile(filepath.Join(root, "splunk", "searches", search))
		if err != nil {
			t.Fatal(err)
		}
		return detection{name, kql[rule], string(spl)}
	}
	generic := load("a tamper check is failing", "tamper.yaml", "tamper-checks-failing.spl")
	sso := load("Platform SSO link changed", "platform-sso-link-changed.yaml", "platform-sso-link-changed.spl")
	detections := []detection{generic,
		load("grant claims", "grant-claim.yaml", "grant-claims-refused-or-not-confirmed.spl"), sso}

	type record struct {
		name string
		r    map[string]any
	}
	var records []record
	var changed map[string]any
	for _, f := range fx {
		records = append(records, record{filepath.ToSlash(f.File), f.Record})
		if analytic(f.Record) == "altiward.tamper.platform_sso_link_changed" {
			changed = f.Record
		}
	}
	if changed == nil {
		t.Fatal("no fixture for altiward.tamper.platform_sso_link_changed")
	}
	// forge copies the changed link's record with another check.
	forge := func(check, severity string, severityID float64) map[string]any {
		var r map[string]any
		b, _ := json.Marshal(changed)
		json.Unmarshal(b, &r)
		r["finding_info"].(map[string]any)["analytic"].(map[string]any)["name"] = "altiward.tamper." + check
		r["unmapped"].(map[string]any)["altiward"].(map[string]any)["detail"].(map[string]any)["check"] = check
		r["severity"], r["severity_id"] = severity, severityID
		return r
	}
	records = append(records,
		record{"a Mac account registered for Platform SSO", forge("platform_sso_link", "Medium", 3)},
		record{"a changed link with its check in capitals", forge("PLATFORM_SSO_LINK_CHANGED", "High", 4)},
	)

	for _, siem := range []struct {
		name    string
		matches func(d detection, r map[string]any) bool
	}{
		{"Sentinel", func(d detection, r map[string]any) bool { return kqlMatches(t, d.kql, r) }},
		{"Splunk", func(d detection, r map[string]any) bool { return splMatches(t, d.spl, r) }},
	} {
		for _, rec := range records {
			name := analytic(rec.r)
			var got []string
			for _, d := range detections {
				if siem.matches(d, rec.r) {
					got = append(got, d.name)
				}
			}
			switch {
			case value(rec.r, "class_uid") != "2004" || !strings.HasPrefix(strings.ToLower(name), "altiward.tamper."):
				if len(got) > 0 {
					t.Errorf("%s, %s (%s): matched by %q, which are for tamper findings", siem.name, rec.name, name, got)
				}
			case name == "altiward.tamper.platform_sso_link":
				if len(got) > 0 {
					t.Errorf("%s, %s: matched by %q, want none: a registration doesn't alert", siem.name, rec.name, got)
				}
			case name == "altiward.tamper.platform_sso_link_changed":
				if len(got) != 1 || got[0] != sso.name {
					t.Errorf("%s, %s: matched by %q, want only %q", siem.name, rec.name, got, sso.name)
				}
			default:
				if len(got) != 1 {
					t.Errorf("%s, %s (%s): matched by %q, want exactly one", siem.name, rec.name, name, got)
				}
			}
		}
	}
}

// analytic is a record's finding_info.analytic.name, "" when it has none.
func analytic(r map[string]any) string {
	return value(r, "finding_info.analytic.name")
}
