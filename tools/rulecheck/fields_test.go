package main

import (
	"reflect"
	"sort"
	"testing"
)

func names(fs []field) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

func TestKQLFields(t *testing.T) {
	q := analyzeKQL(`AltiwardOCSF_CL
| where ClassUid == 2004 and tostring(Ocsf.finding_info.analytic.name) == "altiward.persistence_detected"
| mv-expand Evidence = Ocsf.evidences
| project TimeGenerated, DeviceSerial, UserName, Session = tostring(Ocsf.metadata.correlation_uid),
    Path = tostring(Evidence.file.path), Account = tostring(Ocsf.evidences[0].user.name), Message
`)
	want := []string{"ClassUid", "DeviceSerial", "Message", "Ocsf.evidences", "Ocsf.evidences[0].user.name",
		"Ocsf.finding_info.analytic.name", "Ocsf.metadata.correlation_uid", "TimeGenerated", "UserName", "Evidence.file.path"}
	sort.Strings(want)
	if got := names(q.Fields); !reflect.DeepEqual(got, want) {
		t.Errorf("fields %q\nwant   %q", got, want)
	}
	for _, f := range q.Fields {
		switch f.Name {
		case "Evidence.file.path":
			if !reflect.DeepEqual(f.Paths, []string{"evidences[].file.path"}) {
				t.Errorf("mv-expand alias: %q", f.Paths)
			}
		case "Ocsf.evidences[0].user.name":
			if !reflect.DeepEqual(f.Paths, []string{"evidences[].user.name"}) {
				t.Errorf("index: %q", f.Paths)
			}
		case "UserName":
			if !reflect.DeepEqual(f.Paths, []string{"user.name", "actor.user.name"}) {
				t.Errorf("UserName: %q", f.Paths)
			}
		}
	}
	if !reflect.DeepEqual(q.Classes, []int{2004}) || q.Analytic != (match{Value: "altiward.persistence_detected"}) {
		t.Errorf("scope: classes %v, analytic %+v", q.Classes, q.Analytic)
	}
	if q.Table != "AltiwardOCSF_CL" {
		t.Errorf("table %q", q.Table)
	}

	q = analyzeKQL(`AltiwardOCSF_CL
| where ClassUid == 2004 and tostring(Ocsf.finding_info.analytic.name) startswith "altiward.tamper."`)
	if q.Analytic != (match{Value: "altiward.tamper.", Prefix: true}) {
		t.Errorf("startswith: %+v", q.Analytic)
	}
}

func TestSPLFields(t *testing.T) {
	q := analyzeSPL(`sourcetype="altiward:ocsf" class_uid=2004 finding_info.analytic.name="altiward.tamper.*"
| stats latest(activity_name) as last latest(message) as message latest(severity) as severity by finding_info.uid host
| where last="Create"
| table _time host user.name evidences{}.file.path status_detail`)
	want := []string{"activity_name", "class_uid", "evidences{}.file.path", "finding_info.analytic.name", "finding_info.uid",
		"message", "severity", "status_detail", "user.name"}
	if got := names(q.Fields); !reflect.DeepEqual(got, want) {
		t.Errorf("fields %q\nwant   %q", got, want)
	}
	for _, f := range q.Fields {
		if f.Name == "evidences{}.file.path" && !reflect.DeepEqual(f.Paths, []string{"evidences[].file.path"}) {
			t.Errorf("{}: %q", f.Paths)
		}
	}
	if !reflect.DeepEqual(q.Classes, []int{2004}) || q.Analytic != (match{Value: "altiward.tamper.", Prefix: true}) {
		t.Errorf("scope: classes %v, analytic %+v", q.Classes, q.Analytic)
	}

	q = analyzeSPL(`sourcetype="altiward:ocsf" class_uid=3005 activity_id=1 status_id=1 severity_id>=3 earliest=-7d
| stats count by user.name | where count > 10`)
	if got := names(q.Fields); !reflect.DeepEqual(got, []string{"activity_id", "class_uid", "severity_id", "status_id", "user.name"}) {
		t.Errorf("fields %q", got)
	}
}
