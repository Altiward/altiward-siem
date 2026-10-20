package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseYAML(t *testing.T) {
	doc := `# a comment
id: 8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d
name: "Altiward: a rule"
description: |
  Line one.
    Indented line.

  After a blank line.
requiredDataConnectors: []
triggerThreshold: 0
tactics:
  - Persistence
  - 'PrivilegeEscalation'
query: |
  AltiwardOCSF_CL
  | where ClassUid == 2004
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceSerial
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
tags:
- altiward
`
	got, err := parseYAML(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"id":                     "8f0c6a52-1d3e-4b7a-9c2f-5e6d7a8b9c0d",
		"name":                   "Altiward: a rule",
		"description":            "Line one.\n  Indented line.\n\nAfter a blank line.\n",
		"requiredDataConnectors": []any{},
		"triggerThreshold":       "0",
		"tactics":                []any{"Persistence", "PrivilegeEscalation"},
		"query":                  "AltiwardOCSF_CL\n| where ClassUid == 2004\n",
		"entityMappings": []any{
			map[string]any{"entityType": "Host", "fieldMappings": []any{map[string]any{"identifier": "HostName", "columnName": "DeviceSerial"}}},
			map[string]any{"entityType": "Account", "fieldMappings": []any{map[string]any{"identifier": "Name", "columnName": "UserName"}}},
		},
		"tags": []any{"altiward"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}
}

// Anything outside the subset is refused rather than misread.
func TestParseYAMLRefusesWhatItDoesNotSupport(t *testing.T) {
	for name, doc := range map[string]string{
		"tab":            "id:\tx\n",
		"tab indent":     "tactics:\n\t- Persistence\n",
		"flow map":       "a: {b: c}\n",
		"flow list":      "a: [b, c]\n",
		"anchor":         "a: &x b\n",
		"alias":          "a: *x\n",
		"folded":         "a: >\n  b\n",
		"duplicate key":  "a: b\na: c\n",
		"no colon":       "just text\n",
		"bad indent":     "a:\n  b: c\n d: e\n",
		"unclosed quote": "a: \"b\n",
		"trailing #":     "a: b # comment\n",
	} {
		if _, err := parseYAML(doc); err == nil {
			t.Errorf("%s: parsed %q", name, doc)
		} else if !strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: error without a line number: %v", name, err)
		}
	}
}

// TestRulesReadTheSameInRuby: a full YAML parser reads each rule file the same way, so the
// subset parser doesn't misread one. GitHub's runners have Ruby; elsewhere it's skipped.
func TestRulesReadTheSameInRuby(t *testing.T) {
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("no ruby")
	}
	files, _ := filepath.Glob("../../sentinel/analytics-rules/*.yaml")
	if len(files) == 0 {
		t.Fatal("no rules")
	}
	for _, f := range files {
		out, err := exec.Command("ruby", "-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.safe_load(File.read(ARGV[0])))", f).Output()
		if err != nil {
			t.Fatalf("%s: ruby: %v", f, err)
		}
		var want any
		if err := json.Unmarshal(out, &want); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		got, err := parseYAML(string(b))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !reflect.DeepEqual(got, stringify(want)) {
			t.Errorf("%s reads differently:\nhere %#v\nruby %#v", f, got, stringify(want))
		}
	}
}

// stringify turns JSON numbers and booleans into the strings parseYAML keeps them as.
func stringify(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			v[k] = stringify(x)
		}
		return v
	case []any:
		for i, x := range v {
			v[i] = stringify(x)
		}
		return v
	case float64, bool:
		return fmt.Sprint(v)
	}
	return v
}
