package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// field is one field a query names, as written, and the OCSF paths it reads: any one of
// them existing in a record is enough. "x[]" in a path means any element of the array x.
type field struct {
	Name  string
	Paths []string
}

// match is a filter on finding_info.analytic.name: equal to Value, or starting with it.
type match struct {
	Value  string
	Prefix bool
}

// query is what a check needs to know about a query: the fields it names, and which
// records it can match (by class_uid and analytic name), so its fields are looked for in
// records it could actually return.
type query struct {
	Table    string
	Fields   []field
	Classes  []int
	Analytic match
}

// columns maps AltiwardOCSF_CL's columns to the OCSF fields they're filled from (the
// server's and the forwarder's Sentinel rows: TimeGenerated is the event's time, UserName is
// who acted for a console action, DeviceSerial the Mac acted on).
var columns = map[string][]string{
	"TimeGenerated": {"time"},
	"EventUid":      {"metadata.uid"},
	"TenantUid":     {"metadata.tenant_uid"},
	"SessionUid":    {"metadata.correlation_uid"},
	"ClassUid":      {"class_uid"},
	"ActivityId":    {"activity_id"},
	"SeverityId":    {"severity_id"},
	"DeviceSerial":  {"device.hw_info.serial_number", "unmapped.altiward.detail.serial"},
	"UserName":      {"user.name", "actor.user.name"},
	"Message":       {"message"},
}

var (
	kqlString   = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	kqlWord     = regexp.MustCompile(`\b[A-Za-z_]\w*\b`)
	kqlOcsf     = regexp.MustCompile(`\bOcsf((?:\.[A-Za-z_]\w*|\[\d+\])+)`)
	kqlExpand   = regexp.MustCompile(`mv-expand\s+(\w+)\s*=\s*Ocsf((?:\.[A-Za-z_]\w*)+)`)
	kqlClass    = regexp.MustCompile(`\bClassUid\s*==\s*(\d+)`)
	kqlAnalytic = regexp.MustCompile(`finding_info\.analytic\.name\)\s*(==|startswith)\s*"([^"]+)"`)
	arrayIndex  = regexp.MustCompile(`\[\d+\]`)
	splString   = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	splCompare  = regexp.MustCompile(`([A-Za-z_][\w.{}]*)\s*(?:>=|<=|!=|=|>|<)`)
	splFunc     = regexp.MustCompile(`\b(?:latest|earliest|values|list|first|last|max|min|sum|avg|dc|count)\(([\w.{}]+)\)`)
	splAlias    = regexp.MustCompile(`\bas\s+(\w+)`)
	splEval     = regexp.MustCompile(`\|\s*eval\s+([^|]+)`)
	splAssign   = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=`)
	splQuoted   = regexp.MustCompile(`'([A-Za-z_][\w.{}]*)'`)
	splClause   = regexp.MustCompile(`(?:\|\s*(?:table|fields)|\bby)\s+([^|]+)`)
	splToken    = regexp.MustCompile(`[A-Za-z_][\w.{}]*`)
	splClass    = regexp.MustCompile(`\bclass_uid=(\d+)`)
	splAnalytic = regexp.MustCompile(`\bfinding_info\.analytic\.name="([^"]+)"`)
	// Splunk's own fields, and search and streamstats options that look like comparisons.
	splBuiltIn = map[string]bool{"sourcetype": true, "source": true, "index": true, "host": true, "_time": true, "earliest": true,
		"latest": true, "count": true, "current": true}
)

func (q *query) add(name string, paths ...string) {
	for _, f := range q.Fields {
		if f.Name == name {
			return
		}
	}
	q.Fields = append(q.Fields, field{Name: name, Paths: paths})
}

func (q *query) sort() {
	sort.Slice(q.Fields, func(i, j int) bool { return q.Fields[i].Name < q.Fields[j].Name })
	sort.Ints(q.Classes)
}

func ocsfPath(dotted string) string {
	return arrayIndex.ReplaceAllString(strings.TrimPrefix(dotted, "."), "[]")
}

// analyzeKQL reads a query over AltiwardOCSF_CL: its table (after any let statements), its
// columns, its Ocsf.* paths (through mv-expand aliases too), and its ClassUid and
// analytic-name filters.
func analyzeKQL(kql string) query {
	var lines []string
	for _, l := range strings.Split(kql, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") {
			lines = append(lines, l)
		}
	}
	raw := strings.Join(lines, "\n")
	var q query
	code := kqlString.ReplaceAllString(raw, `""`)
	// let statements end with ";"; the query that reads the table is the last statement.
	stmts := strings.Split(code, ";")
	if w := kqlWord.FindString(stmts[len(stmts)-1]); w != "" {
		q.Table = w
	}
	for _, m := range kqlClass.FindAllStringSubmatch(raw, -1) {
		n, _ := strconv.Atoi(m[1])
		q.Classes = append(q.Classes, n)
	}
	if m := kqlAnalytic.FindStringSubmatch(raw); m != nil {
		q.Analytic = match{Value: m[2], Prefix: m[1] == "startswith"}
	}
	for _, w := range kqlWord.FindAllString(code, -1) {
		if paths, ok := columns[w]; ok {
			q.add(w, paths...)
		}
	}
	for _, m := range kqlOcsf.FindAllStringSubmatch(code, -1) {
		q.add("Ocsf"+m[1], ocsfPath(m[1]))
	}
	for _, m := range kqlExpand.FindAllStringSubmatch(code, -1) {
		alias, base := m[1], ocsfPath(m[2])
		uses := regexp.MustCompile(`\b` + regexp.QuoteMeta(alias) + `((?:\.[A-Za-z_]\w*)+)`)
		for _, u := range uses.FindAllStringSubmatch(code, -1) {
			q.add(alias+u[1], base+"[]"+u[1])
		}
	}
	q.sort()
	return q
}

// analyzeSPL reads a search over altiward:ocsf events: the fields it compares, aggregates,
// tables, groups by or names in single quotes (fields made with eval or "as" and Splunk's
// own fields left out), and its class_uid and analytic-name filters.
func analyzeSPL(spl string) query {
	var q query
	for _, m := range splClass.FindAllStringSubmatch(spl, -1) {
		n, _ := strconv.Atoi(m[1])
		q.Classes = append(q.Classes, n)
	}
	if m := splAnalytic.FindStringSubmatch(spl); m != nil {
		v, prefix := strings.CutSuffix(m[1], "*")
		q.Analytic = match{Value: v, Prefix: prefix}
	}
	code := splString.ReplaceAllString(spl, `""`)
	aliases := map[string]bool{}
	for _, m := range splAlias.FindAllStringSubmatch(code, -1) {
		aliases[m[1]] = true
	}
	made := evalFields(code)
	code = splAlias.ReplaceAllString(code, "")
	var names []string
	for _, m := range splQuoted.FindAllStringSubmatch(code, -1) {
		names = append(names, m[1])
	}
	for _, m := range splCompare.FindAllStringSubmatch(code, -1) {
		names = append(names, m[1])
	}
	for _, m := range splFunc.FindAllStringSubmatch(code, -1) {
		names = append(names, m[1])
	}
	for _, m := range splClause.FindAllStringSubmatch(code, -1) {
		names = append(names, splToken.FindAllString(m[1], -1)...)
	}
	for _, n := range names {
		if splBuiltIn[n] || made[n] || aliases[n] && !strings.Contains(n, ".") && !isAggregated(code, n) {
			continue
		}
		q.add(n, strings.ReplaceAll(n, "{}", "[]"))
	}
	q.sort()
	return q
}

// evalFields is the fields eval commands make: the name before each "=" in eval x=..., y=...
func evalFields(code string) map[string]bool {
	made := map[string]bool{}
	for _, m := range splEval.FindAllStringSubmatch(code, -1) {
		// Split the assignments at commas outside parentheses.
		depth, start := 0, 0
		expr := m[1] + ","
		for i, c := range expr {
			switch {
			case c == '(':
				depth++
			case c == ')':
				depth--
			case c == ',' && depth == 0:
				if a := splAssign.FindStringSubmatch(expr[start:i]); a != nil {
					made[a[1]] = true
				}
				start = i + 1
			}
		}
	}
	return made
}

// isAggregated reports whether an alias is also a field read by a function, as in
// latest(message) as message: then the field is real, and checked.
func isAggregated(code, name string) bool {
	for _, m := range splFunc.FindAllStringSubmatch(code, -1) {
		if m[1] == name {
			return true
		}
	}
	return false
}
