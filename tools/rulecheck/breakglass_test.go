package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The break-glass rule and saved search must match only the console's own records. A Mac's
// serial is the actor of its key rotation (agent.enrollment, class 6003), and a Mac
// account's name is the user of admin.permanent_use (class 3002): whoever enrols a Mac or
// names an account chooses them, so either can start with break-glass:. The checks only
// look at classes and analytic names, so this test reads the two filters and runs them on
// the fixtures, and on those two records with break-glass: put in.
func TestBreakGlassMatchesOnlyConsoleRecords(t *testing.T) {
	const root = "../.."
	fx, errs := loadFixtures(root)
	rules, ruleErrs := loadRules(root)
	if errs = append(errs, ruleErrs...); len(errs) > 0 {
		t.Fatal(errs)
	}
	var kql string
	for _, r := range rules {
		if filepath.ToSlash(r.File) == "sentinel/analytics-rules/break-glass-token.yaml" {
			kql = r.Query
		}
	}
	if kql == "" {
		t.Fatal("no sentinel/analytics-rules/break-glass-token.yaml")
	}
	spl, err := os.ReadFile(filepath.Join(root, "splunk", "searches", "break-glass-token-use.spl"))
	if err != nil {
		t.Fatal(err)
	}

	type record struct {
		name string
		r    map[string]any
		want bool
	}
	var records []record
	for _, f := range fx {
		file, user := filepath.ToSlash(f.File), userName(f.Record)
		records = append(records, record{
			name: fmt.Sprintf("%s (%v, %q)", file, lookup(f.Record, "unmapped", "altiward", "event_type"), user),
			r:    f.Record,
			want: file == "fixtures/altiward/console-activity.json" && strings.HasPrefix(user, "break-glass:"),
		})
	}
	// forge copies a fixture's first record with break-glass: at path.
	forge := func(file string, path ...string) map[string]any {
		var r map[string]any
		for _, f := range fx {
			if filepath.Base(f.File) == file {
				b, _ := json.Marshal(f.Record)
				json.Unmarshal(b, &r)
				break
			}
		}
		if r == nil {
			t.Fatalf("no fixture %s", file)
		}
		m := r
		for _, k := range path[:len(path)-1] {
			m = m[k].(map[string]any)
		}
		m[path[len(path)-1]] = "break-glass:3f2a9c1b"
		return r
	}
	records = append(records,
		record{name: "a Mac enrolled with the serial break-glass:3f2a9c1b rotates its key",
			r: forge("agent-enrollment-rotated.json", "actor", "user", "name")},
		record{name: "a Mac account named break-glass:3f2a9c1b is used",
			r: forge("admin-permanent-use-started.json", "user", "name")},
	)

	wanted := 0
	for _, rec := range records {
		if got := kqlMatches(t, kql, rec.r); got != rec.want {
			t.Errorf("Sentinel rule, %s: matches %v, want %v", rec.name, got, rec.want)
		}
		if got := splMatches(t, string(spl), rec.r); got != rec.want {
			t.Errorf("Splunk search, %s: matches %v, want %v", rec.name, got, rec.want)
		}
		if rec.want {
			wanted++
		}
	}
	// The console's break-glass sign-in (3002) and change (6003).
	if wanted != 2 {
		t.Errorf("want 2 break-glass console fixtures, found %d", wanted)
	}
}

// userName is AltiwardOCSF_CL's UserName for a record: user.name, else actor.user.name.
func userName(r map[string]any) string {
	if s := value(r, "user.name"); s != "" {
		return s
	}
	return value(r, "actor.user.name")
}

// value is the record's value at a dotted path as text, "" when it has none.
func value(r map[string]any, path string) string {
	switch v := lookup(r, strings.Split(path, ".")...).(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

var (
	kqlWhere = regexp.MustCompile(`(?m)^\s*\|\s*where\s+(.+)$`)
	kqlTerm  = regexp.MustCompile(`^(?:ClassUid\s*==\s*(\d+)|ClassUid\s+in\s*\(([\d\s,]+)\)|` +
		`(\w+|tostring\(Ocsf((?:\.\w+)+)\))\s+(==|startswith)\s+"([^"]*)")$`)
)

// kqlMatches runs a query's where filters on one record. It reads what the break-glass rule
// uses: terms joined by "and", each ClassUid == n, ClassUid in (...), or a column or
// tostring(Ocsf.path) compared to a string with == or startswith (which, as in KQL, ignores
// case). The ingestion-time window is left out: every fixture would be in it.
func kqlMatches(t *testing.T, kql string, r map[string]any) bool {
	t.Helper()
	for _, w := range kqlWhere.FindAllStringSubmatch(kql, -1) {
		for _, term := range strings.Split(strings.TrimSpace(w[1]), " and ") {
			term = strings.TrimSpace(term)
			if strings.HasPrefix(term, "ingestion_time() ") {
				continue
			}
			m := kqlTerm.FindStringSubmatch(term)
			if m == nil {
				t.Fatalf("can't run the KQL term %q", term)
			}
			var ok bool
			switch {
			case m[1] != "":
				ok = value(r, "class_uid") == m[1]
			case m[2] != "":
				for _, n := range kqlNumber.FindAllString(m[2], -1) {
					ok = ok || value(r, "class_uid") == n
				}
			default:
				var got string
				if m[4] != "" {
					got = value(r, strings.TrimPrefix(m[4], "."))
				} else if m[3] == "UserName" {
					got = userName(r)
				} else if paths, known := columns[m[3]]; known {
					got = value(r, paths[0])
				} else {
					t.Fatalf("can't run the KQL term %q: no column %s", term, m[3])
				}
				if m[5] == "==" {
					ok = got == m[6]
				} else {
					ok = strings.HasPrefix(strings.ToLower(got), strings.ToLower(m[6]))
				}
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

// splMatches runs a search's first command (the text before the first |) on one record:
// field=value terms, where * matches anything and case doesn't matter, as in Splunk, joined
// by spaces or AND, by OR, and in parentheses. sourcetype and the time bounds are left out:
// every fixture would pass them.
func splMatches(t *testing.T, spl string, r map[string]any) bool {
	t.Helper()
	first, _, _ := strings.Cut(spl, "|")
	p := &splParser{t: t, r: r, tokens: splTokens(first)}
	ok := p.or()
	if p.i != len(p.tokens) {
		t.Fatalf("can't run the search: stopped at %q", p.tokens[p.i])
	}
	return ok
}

// splTokens splits a search into parentheses and terms, keeping quoted values whole.
func splTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		switch {
		case strings.ContainsRune(" \t\n", rune(s[i])):
			i++
		case s[i] == '(' || s[i] == ')':
			out = append(out, s[i:i+1])
			i++
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n()", rune(s[j])) {
				if s[j] == '"' {
					if k := strings.IndexByte(s[j+1:], '"'); k >= 0 {
						j += k + 2
						continue
					}
				}
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

type splParser struct {
	t      *testing.T
	r      map[string]any
	tokens []string
	i      int
}

func (p *splParser) peek() string {
	if p.i < len(p.tokens) {
		return p.tokens[p.i]
	}
	return ""
}

func (p *splParser) or() bool {
	ok := p.and()
	for p.peek() == "OR" {
		p.i++
		next := p.and()
		ok = ok || next
	}
	return ok
}

func (p *splParser) and() bool {
	ok := true
	for p.i < len(p.tokens) && p.peek() != ")" && p.peek() != "OR" {
		if p.peek() == "AND" {
			p.i++
			continue
		}
		next := p.term()
		ok = ok && next
	}
	return ok
}

func (p *splParser) term() bool {
	tok := p.tokens[p.i]
	p.i++
	switch tok {
	case "(":
		ok := p.or()
		if p.peek() != ")" {
			p.t.Fatal("can't run the search: a ( isn't closed")
		}
		p.i++
		return ok
	case "NOT":
		return !p.term()
	}
	field, want, found := strings.Cut(tok, "=")
	if !found {
		p.t.Fatalf("can't run the search term %q", tok)
	}
	switch field {
	case "sourcetype", "index", "earliest", "latest", "_index_earliest", "_index_latest":
		return true
	}
	pattern := strings.ReplaceAll(regexp.QuoteMeta(strings.Trim(want, `"`)), `\*`, ".*")
	got := value(p.r, field)
	return got != "" && regexp.MustCompile("(?i)^"+pattern+"$").MatchString(got)
}
