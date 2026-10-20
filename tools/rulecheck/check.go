package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// fixture is one OCSF record from fixtures/<source>/: altiward (the server's golden
// examples) or forwarder (altiward-forwarder's).
type fixture struct {
	Source string
	File   string
	Record map[string]any
}

func loadFixtures(root string) ([]fixture, []error) {
	var out []fixture
	var errs []error
	for _, source := range tagNames {
		dir := filepath.Join("fixtures", source)
		files, _ := filepath.Glob(filepath.Join(root, dir, "*.json"))
		sort.Strings(files)
		if len(files) == 0 {
			errs = append(errs, fmt.Errorf("%s has no fixtures: run scripts/sync-fixtures.sh", dir))
		}
		for _, f := range files {
			rel, _ := filepath.Rel(root, f)
			b, err := os.ReadFile(f)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			var records []map[string]any
			if err := json.Unmarshal(b, &records); err != nil {
				errs = append(errs, fmt.Errorf("%s: want a JSON array of records: %w", rel, err))
				continue
			}
			for _, r := range records {
				out = append(out, fixture{Source: source, File: rel, Record: r})
			}
		}
	}
	return out, errs
}

// has reports whether path ("a.b", "a[].b" for any element of the array a) is in v.
func has(v any, path []string) bool {
	if len(path) == 0 {
		return v != nil
	}
	key, array := strings.CutSuffix(path[0], "[]")
	m, ok := v.(map[string]any)
	if !ok || m[key] == nil {
		return false
	}
	if !array {
		return has(m[key], path[1:])
	}
	list, _ := m[key].([]any)
	for _, item := range list {
		if has(item, path[1:]) {
			return true
		}
	}
	return false
}

func lookup(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// matches reports whether a query could return this record: the class and analytic name
// it filters on, if any.
func (q query) matches(r map[string]any) bool {
	if len(q.Classes) > 0 {
		class, _ := r["class_uid"].(float64)
		if !slices.Contains(q.Classes, int(class)) {
			return false
		}
	}
	if q.Analytic.Value != "" {
		name, _ := lookup(r, "finding_info", "analytic", "name").(string)
		if name != q.Analytic.Value && !(q.Analytic.Prefix && strings.HasPrefix(name, q.Analytic.Value)) {
			return false
		}
	}
	return true
}

// checkFields checks, for each tag, that some fixture from that source is a record the query
// can match, and that every field it names is in at least one of those.
func checkFields(where string, q query, tags []string, fx []fixture) []error {
	var errs []error
	for _, tag := range tags {
		var scope []fixture
		for _, f := range fx {
			if f.Source == tag && q.matches(f.Record) {
				scope = append(scope, f)
			}
		}
		if len(scope) == 0 {
			errs = append(errs, fmt.Errorf("%s: tagged %s, but no %s fixture is a record it can match (class_uid %v, analytic %q): "+
				"add an example, or drop the tag", where, tag, tag, q.Classes, q.Analytic.Value))
			continue
		}
		for _, field := range q.Fields {
			found := false
			for _, f := range scope {
				for _, p := range field.Paths {
					if has(f.Record, strings.Split(p, ".")) {
						found = true
					}
				}
			}
			if !found {
				errs = append(errs, fmt.Errorf("%s: %s (%s) isn't in any %s fixture it can match", where, field.Name,
					strings.Join(field.Paths, " or "), tag))
			}
		}
	}
	return errs
}

// checkHunting checks sentinel/hunting/*.kql: a "// Tags:" line in the header comment, the
// table, and the fields.
func checkHunting(root string, fx []fixture) []error {
	files, _ := filepath.Glob(filepath.Join(root, "sentinel", "hunting", "*.kql"))
	sort.Strings(files)
	var errs []error
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var tags []string
		found := false
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, "//") {
				break
			}
			if m := tagsLine.FindStringSubmatch(l); m != nil {
				tags, found = splitTags(m[1]), true
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("%s: start with a // comment saying what it finds, then \"// Tags: altiward\" (or altiward, forwarder)", rel))
		}
		for _, p := range checkTags(tags) {
			errs = append(errs, fmt.Errorf("%s: %s", rel, p))
		}
		q := analyzeKQL(string(b))
		if q.Table != tableName {
			errs = append(errs, fmt.Errorf("%s: the query must read %s, not %s", rel, tableName, q.Table))
		}
		errs = append(errs, checkFields(rel, q, tags, fx)...)
	}
	if len(files) == 0 {
		errs = append(errs, fmt.Errorf("sentinel/hunting has no queries"))
	}
	return errs
}

// check runs every check on the repository at root.
func check(root string) []error {
	fx, errs := loadFixtures(root)
	rules, ruleErrs := loadRules(root)
	errs = append(errs, ruleErrs...)
	for _, r := range rules {
		errs = append(errs, checkFields(r.File, analyzeKQL(r.Query), r.Tags, fx)...)
	}
	errs = append(errs, checkHunting(root, fx)...)
	errs = append(errs, checkSplunk(root, fx)...)
	if len(ruleErrs) == 0 {
		const arm = "sentinel/azuredeploy.json"
		want, err := buildARM(rules)
		got, _ := os.ReadFile(filepath.Join(root, arm))
		switch {
		case err != nil:
			errs = append(errs, err)
		case !bytes.Equal(got, want):
			errs = append(errs, fmt.Errorf("%s is out of date: run scripts/build-arm.sh", arm))
		}
	}
	return errs
}
