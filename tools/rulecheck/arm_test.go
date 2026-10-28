package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestISODuration(t *testing.T) {
	for in, want := range map[string]string{"5m": "PT5M", "15m": "PT15M", "1h": "PT1H", "1d": "P1D", "7d": "P7D", "14d": "P14D"} {
		if got := isoDuration(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestBuildARM(t *testing.T) {
	v, err := parseYAML(goodRule)
	if err != nil {
		t.Fatal(err)
	}
	r, problems := parseRule(v.(map[string]any))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	r.Description = "[Not an expression] " + r.Description
	b, err := buildARM([]rule{r})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "}\n") || strings.Contains(string(b), `<`) {
		t.Errorf("want indented JSON with < and > as they are, ending in a newline")
	}
	var tmpl struct {
		Schema     string `json:"$schema"`
		Parameters map[string]struct {
			Type string
		}
		Resources []struct {
			Type, APIVersion, Scope, Name, Kind string
			Properties                          map[string]any
		}
	}
	if err := json.Unmarshal(b, &tmpl); err != nil {
		t.Fatal(err)
	}
	if len(tmpl.Parameters) != 1 || tmpl.Parameters["workspace"].Type != "string" || len(tmpl.Resources) != 1 {
		t.Fatalf("parameters %v, %d resources", tmpl.Parameters, len(tmpl.Resources))
	}
	res := tmpl.Resources[0]
	if res.Type != "Microsoft.SecurityInsights/alertRules" || res.APIVersion != "2024-09-01" || res.Kind != "Scheduled" ||
		res.Name != "8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d" ||
		res.Scope != "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspace'))]" {
		t.Errorf("resource %+v", res)
	}
	p := res.Properties
	for k, want := range map[string]any{
		"displayName": "Altiward: persistence while admin", "severity": "High", "enabled": true,
		"queryFrequency": "PT1H", "queryPeriod": "PT1H", "triggerOperator": "GreaterThan", "triggerThreshold": 0.0,
		"suppressionEnabled": false, "suppressionDuration": "PT1H", "templateVersion": "1.0.0",
		"description": "[[Not an expression] Persistence that appeared while someone was admin.\n",
	} {
		if p[k] != want {
			t.Errorf("%s = %#v, want %#v", k, p[k], want)
		}
	}
	if !reflect.DeepEqual(p["tactics"], []any{"Persistence"}) || !reflect.DeepEqual(p["techniques"], []any{"T1543", "T1098"}) {
		t.Errorf("tactics %v, techniques %v (the API takes parent techniques only)", p["tactics"], p["techniques"])
	}
	if !strings.HasPrefix(p["query"].(string), "AltiwardOCSF_CL\n") {
		t.Errorf("query %q", p["query"])
	}
	want := []any{map[string]any{"entityType": "Host", "fieldMappings": []any{map[string]any{"identifier": "HostName", "columnName": "DeviceSerial"}}}}
	if !reflect.DeepEqual(p["entityMappings"], want) {
		t.Errorf("entityMappings %v", p["entityMappings"])
	}
	if p["eventGroupingSettings"].(map[string]any)["aggregationKind"] != "AlertPerResult" {
		t.Errorf("eventGroupingSettings %v", p["eventGroupingSettings"])
	}
	if _, ok := p["alertDetailsOverride"]; ok {
		t.Errorf("alertDetailsOverride %v, want none", p["alertDetailsOverride"])
	}

	// A severity column becomes alertDetailsOverride.
	v, err = parseYAML(strings.Replace(goodRule, "kind: Scheduled\n",
		"alertDetailsOverride:\n  alertSeverityColumnName: UserName\nkind: Scheduled\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	if r, problems = parseRule(v.(map[string]any)); len(problems) > 0 {
		t.Fatal(problems)
	}
	if b, err = buildARM([]rule{r}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\"alertDetailsOverride\": {\n          \"alertSeverityColumnName\": \"UserName\"\n        }") {
		t.Errorf("no alertDetailsOverride in\n%s", b)
	}
}
