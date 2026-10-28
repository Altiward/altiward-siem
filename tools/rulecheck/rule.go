package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// rule is one Sentinel analytics rule, in the YAML schema Microsoft's Azure-Sentinel
// repository uses for scheduled rules, plus tags saying whose events it needs.
type rule struct {
	File               string // relative to the repository
	ID                 string
	Name               string
	Description        string
	Severity           string
	QueryFrequency     string
	QueryPeriod        string
	TriggerOperator    string
	TriggerThreshold   int
	Tactics            []string
	RelevantTechniques []string
	Query              string
	EntityMappings     []entityMapping
	// AlertDetailsOverride is alertDetailsOverride: only alertSeverityColumnName, a column
	// the query returns that gives each alert's severity in place of Severity.
	AlertDetailsOverride map[string]string
	Tags                 []string
	Version              string
}

type entityMapping struct {
	EntityType    string         `json:"entityType"`
	FieldMappings []fieldMapping `json:"fieldMappings"`
}

type fieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}

var (
	ruleKeys = []string{"id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency", "queryPeriod",
		"triggerOperator", "triggerThreshold", "tactics", "relevantTechniques", "query", "entityMappings", "alertDetailsOverride", "tags", "version", "kind"}
	severities = []string{"High", "Medium", "Low", "Informational"}
	// The tactics and entity types Sentinel's alertRules API (2024-09-01) accepts.
	tactics = []string{"Collection", "CommandAndControl", "CredentialAccess", "DefenseEvasion", "Discovery", "Execution",
		"Exfiltration", "Impact", "ImpairProcessControl", "InhibitResponseFunction", "InitialAccess", "LateralMovement",
		"Persistence", "PreAttack", "PrivilegeEscalation", "Reconnaissance", "ResourceDevelopment"}
	entityTypes = []string{"Account", "AzureResource", "CloudApplication", "DNS", "File", "FileHash", "Host", "IP", "Mailbox",
		"MailCluster", "MailMessage", "Malware", "Process", "RegistryKey", "RegistryValue", "SecurityGroup", "SubmissionMail", "URL"}
	operators  = map[string]string{"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
	tagNames   = []string{"altiward", "forwarder"}
	guid       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	technique  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	semver     = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	duration   = regexp.MustCompile(`^([1-9]\d*)([mhd])$`)
	tableName  = "AltiwardOCSF_CL"
	maxMinutes = 14 * 24 * 60
)

// minutes reads a rule duration (5m, 1h, 7d); -1 when it isn't one.
func minutes(d string) int {
	m := duration.FindStringSubmatch(d)
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(m[1])
	return n * map[string]int{"m": 1, "h": 60, "d": 24 * 60}[m[2]]
}

func str(v map[string]any, key string, problems *[]string) string {
	s, ok := v[key].(string)
	if !ok || strings.TrimSpace(s) == "" {
		*problems = append(*problems, key+" is required")
	}
	return s
}

func strs(v map[string]any, key string, problems *[]string) []string {
	list, ok := v[key].([]any)
	if !ok {
		*problems = append(*problems, key+" must be a list")
		return nil
	}
	var out []string
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			*problems = append(*problems, key+" must be a list of strings")
			continue
		}
		out = append(out, s)
	}
	return out
}

// parseRule reads and checks a rule's keys and values. Its query's fields are checked
// against the fixtures separately.
func parseRule(v map[string]any) (rule, []string) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for key := range v {
		if !slices.Contains(ruleKeys, key) {
			add("%s isn't a key this repository's rules use", key)
		}
	}
	r := rule{
		ID: str(v, "id", &problems), Name: str(v, "name", &problems), Description: str(v, "description", &problems),
		Severity: str(v, "severity", &problems), QueryFrequency: str(v, "queryFrequency", &problems),
		QueryPeriod: str(v, "queryPeriod", &problems), TriggerOperator: str(v, "triggerOperator", &problems),
		Query: str(v, "query", &problems), Version: str(v, "version", &problems),
		Tactics: strs(v, "tactics", &problems), RelevantTechniques: strs(v, "relevantTechniques", &problems),
		Tags: strs(v, "tags", &problems),
	}
	if r.ID != "" && !guid.MatchString(r.ID) {
		add("id %q must be a lowercase GUID (uuidgen | tr A-Z a-z)", r.ID)
	}
	if r.Name != "" && !strings.HasPrefix(r.Name, "Altiward: ") {
		add("name must start with \"Altiward: \", so the rule is easy to find in Sentinel")
	}
	if r.Severity != "" && !slices.Contains(severities, r.Severity) {
		add("severity %q: want one of %s", r.Severity, strings.Join(severities, ", "))
	}
	if k, _ := v["kind"].(string); k != "Scheduled" {
		add("kind must be Scheduled")
	}
	if _, ok := v["requiredDataConnectors"].([]any); !ok {
		add("requiredDataConnectors must be a list ([] for the AltiwardOCSF_CL table)")
	}
	if r.TriggerOperator != "" && operators[r.TriggerOperator] == "" {
		add("triggerOperator %q: want gt, lt, eq or ne", r.TriggerOperator)
	}
	if s, ok := v["triggerThreshold"].(string); !ok {
		add("triggerThreshold is required")
	} else if n, err := strconv.Atoi(s); err != nil || n < 0 || n > 10000 {
		add("triggerThreshold %q: want a number from 0 to 10000", s)
	} else {
		r.TriggerThreshold = n
	}
	freq, period := minutes(r.QueryFrequency), minutes(r.QueryPeriod)
	if r.QueryFrequency != "" && (freq < 5 || freq > maxMinutes) {
		add("queryFrequency %q: want a duration from 5m to 14d, such as 1h", r.QueryFrequency)
	}
	if r.QueryPeriod != "" && (period < 5 || period > maxMinutes || freq > 0 && period < freq) {
		add("queryPeriod %q: want a duration from queryFrequency to 14d", r.QueryPeriod)
	}
	if len(r.Tactics) == 0 {
		add("tactics needs at least one tactic")
	}
	for _, t := range r.Tactics {
		if !slices.Contains(tactics, t) {
			add("tactic %q isn't one Sentinel accepts", t)
		}
	}
	for _, t := range r.RelevantTechniques {
		if !technique.MatchString(t) {
			add("technique %q: want a MITRE ATT&CK ID such as T1136 or T1136.001", t)
		}
	}
	if r.Version != "" && !semver.MatchString(r.Version) {
		add("version %q: want major.minor.patch", r.Version)
	}
	problems = append(problems, checkTags(r.Tags)...)
	if q := analyzeKQL(r.Query); r.Query != "" && q.Table != tableName {
		add("the query must read %s, not %s", tableName, q.Table)
	}

	list, ok := v["entityMappings"].([]any)
	if !ok || len(list) == 0 {
		add("entityMappings needs at least one entity, such as the Host from DeviceSerial")
	}
	words := map[string]bool{}
	for _, w := range kqlWord.FindAllString(r.Query, -1) {
		words[w] = true
	}
	for _, item := range list {
		m, _ := item.(map[string]any)
		e := entityMapping{EntityType: fmt.Sprint(m["entityType"])}
		if !slices.Contains(entityTypes, e.EntityType) {
			add("entityType %q isn't one Sentinel accepts", e.EntityType)
		}
		fields, _ := m["fieldMappings"].([]any)
		if len(fields) == 0 {
			add("entity %s needs fieldMappings", e.EntityType)
		}
		for _, f := range fields {
			fm, _ := f.(map[string]any)
			mapping := fieldMapping{Identifier: fmt.Sprint(fm["identifier"]), ColumnName: fmt.Sprint(fm["columnName"])}
			if !words[mapping.ColumnName] {
				add("entity %s maps column %s, which the query doesn't return", e.EntityType, mapping.ColumnName)
			}
			e.FieldMappings = append(e.FieldMappings, mapping)
		}
		r.EntityMappings = append(r.EntityMappings, e)
	}

	if o, ok := v["alertDetailsOverride"]; ok {
		m, _ := o.(map[string]any)
		col, _ := m["alertSeverityColumnName"].(string)
		switch {
		case len(m) != 1 || col == "":
			add("alertDetailsOverride takes only alertSeverityColumnName")
		case !words[col]:
			add("alertDetailsOverride's alertSeverityColumnName %s isn't a column the query returns", col)
		default:
			r.AlertDetailsOverride = map[string]string{"alertSeverityColumnName": col}
		}
	}
	return r, problems
}

func checkTags(tags []string) []string {
	if len(tags) == 0 {
		return []string{"tags needs altiward, forwarder or both: whose events the rule works on"}
	}
	var problems []string
	for i, t := range tags {
		if !slices.Contains(tagNames, t) {
			problems = append(problems, fmt.Sprintf("tag %q: want altiward or forwarder", t))
		}
		if slices.Contains(tags[:i], t) {
			problems = append(problems, fmt.Sprintf("tag %q appears twice", t))
		}
	}
	return problems
}

// loadRules reads sentinel/analytics-rules/*.yaml, in file order.
func loadRules(root string) ([]rule, []error) {
	files, _ := filepath.Glob(filepath.Join(root, "sentinel", "analytics-rules", "*.yaml"))
	sort.Strings(files)
	var rules []rule
	var errs []error
	ids := map[string]string{}
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		v, err := parseYAML(string(b))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: want a mapping", rel))
			continue
		}
		r, problems := parseRule(m)
		r.File = rel
		for _, p := range problems {
			errs = append(errs, fmt.Errorf("%s: %s", rel, p))
		}
		if other, dup := ids[r.ID]; dup && r.ID != "" {
			errs = append(errs, fmt.Errorf("%s: id %s is %s's too", rel, r.ID, other))
		}
		ids[r.ID] = rel
		rules = append(rules, r)
	}
	if len(files) == 0 {
		errs = append(errs, fmt.Errorf("sentinel/analytics-rules has no rules"))
	}
	return rules, errs
}
