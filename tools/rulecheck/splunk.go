package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// stanza is one saved search in splunk/savedsearches.conf. The comment line
// "# Tags: altiward, forwarder" just above it says whose events it works on.
type stanza struct {
	Name string
	Line int
	Tags []string
	Keys map[string]string
}

var (
	confRequired = []string{"description", "search", "dispatch.earliest_time", "dispatch.latest_time", "cron_schedule", "enableSched"}
	confAllowed  = append(slices.Clone(confRequired), "counttype", "relation", "quantity", "alert.track", "alert.severity",
		"alert.suppress", "alert.suppress.period", "alert.suppress.fields", "alert.digest_mode")
	confKey  = regexp.MustCompile(`^([A-Za-z0-9_.]+)\s*=\s?(.*)$`)
	nonSlug  = regexp.MustCompile(`[^a-z0-9]+`)
	tagsLine = regexp.MustCompile(`^(?://|#)\s*Tags:\s*(.*)$`)
)

// parseConf reads a .conf file: [stanza] headers, key = value lines (a trailing \ continues
// a value on the next line, keeping the line break) and # comments.
func parseConf(text string) ([]stanza, []string) {
	var out []stanza
	var problems []string
	var tags []string
	sc := bufio.NewScanner(strings.NewReader(text))
	line := 0
	var cur *stanza
	for sc.Scan() {
		line++
		l := strings.TrimRight(sc.Text(), " ")
		switch {
		case l == "":
		case strings.HasPrefix(l, "#"):
			if m := tagsLine.FindStringSubmatch(l); m != nil {
				tags = splitTags(m[1])
			}
		case strings.HasPrefix(l, "["):
			if !strings.HasSuffix(l, "]") {
				problems = append(problems, fmt.Sprintf("line %d: an unclosed [stanza]", line))
				continue
			}
			out = append(out, stanza{Name: l[1 : len(l)-1], Line: line, Tags: tags, Keys: map[string]string{}})
			cur, tags = &out[len(out)-1], nil
		default:
			m := confKey.FindStringSubmatch(l)
			if m == nil || cur == nil {
				problems = append(problems, fmt.Sprintf("line %d: want key = value inside a [stanza]", line))
				continue
			}
			value := m[2]
			for strings.HasSuffix(value, `\`) && sc.Scan() {
				line++
				value = strings.TrimRight(strings.TrimSuffix(value, `\`), " ") + "\n" + strings.TrimRight(sc.Text(), " ")
			}
			if _, dup := cur.Keys[m[1]]; dup {
				problems = append(problems, fmt.Sprintf("line %d: %s appears twice in [%s]", line, m[1], cur.Name))
			}
			cur.Keys[m[1]] = value
		}
	}
	return out, problems
}

func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

// searchFile is the .spl file a saved search's text is kept in, named after its title.
func searchFile(name string) string {
	slug := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimPrefix(name, "Altiward - ")), "-")
	return strings.Trim(slug, "-") + ".spl"
}

// checkSplunk checks savedsearches.conf against splunk/searches/*.spl and the fixtures.
func checkSplunk(root string, fx []fixture) []error {
	const conf = "splunk/savedsearches.conf"
	b, err := os.ReadFile(filepath.Join(root, conf))
	if err != nil {
		return []error{err}
	}
	stanzas, problems := parseConf(string(b))
	var errs []error
	for _, p := range problems {
		errs = append(errs, fmt.Errorf("%s: %s", conf, p))
	}
	files, _ := filepath.Glob(filepath.Join(root, "splunk", "searches", "*.spl"))
	used := map[string]bool{}
	for _, s := range stanzas {
		where := fmt.Sprintf("%s [%s]", conf, s.Name)
		bad := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, args...)))
		}
		if !strings.HasPrefix(s.Name, "Altiward - ") {
			bad("saved search names start with \"Altiward - \"")
		}
		for _, k := range confRequired {
			if strings.TrimSpace(s.Keys[k]) == "" {
				bad("%s is required", k)
			}
		}
		for k := range s.Keys {
			if !slices.Contains(confAllowed, k) {
				bad("%s isn't a key this repository's searches use", k)
			}
		}
		if len(s.Tags) == 0 {
			bad("put \"# Tags: altiward\" (or altiward, forwarder) on the line above the stanza")
		}
		for _, p := range checkTags(s.Tags) {
			bad("%s", p)
		}
		search := strings.TrimSpace(s.Keys["search"])
		if !strings.HasPrefix(search, `sourcetype="altiward:ocsf"`) {
			bad(`the search must start with sourcetype="altiward:ocsf"`)
		}
		file := filepath.Join("splunk", "searches", searchFile(s.Name))
		used[file] = true
		spl, err := os.ReadFile(filepath.Join(root, file))
		switch {
		case err != nil:
			bad("its search must also be in %s", file)
		case strings.TrimSpace(string(spl)) != search:
			bad("its search differs from %s; keep them the same", file)
		}
		errs = append(errs, checkFields(where, analyzeSPL(search), s.Tags, fx)...)
	}
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		if !used[rel] {
			errs = append(errs, fmt.Errorf("%s: no saved search in %s uses it", rel, conf))
		}
	}
	if len(stanzas) == 0 {
		errs = append(errs, fmt.Errorf("%s has no saved searches", conf))
	}
	return errs
}
