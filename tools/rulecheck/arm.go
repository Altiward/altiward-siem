package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
)

// The ARM template deploys every rule to one workspace, as Microsoft.SecurityInsights
// alertRules extension resources on it.
const armAPIVersion = "2024-09-01"

type armTemplate struct {
	Schema         string              `json:"$schema"`
	ContentVersion string              `json:"contentVersion"`
	Parameters     map[string]armParam `json:"parameters"`
	Resources      []armResource       `json:"resources"`
}

type armParam struct {
	Type     string            `json:"type"`
	Metadata map[string]string `json:"metadata"`
}

type armResource struct {
	Type       string   `json:"type"`
	APIVersion string   `json:"apiVersion"`
	Scope      string   `json:"scope"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Properties armRules `json:"properties"`
}

type armRules struct {
	DisplayName           string            `json:"displayName"`
	Description           string            `json:"description"`
	Severity              string            `json:"severity"`
	Enabled               bool              `json:"enabled"`
	Query                 string            `json:"query"`
	QueryFrequency        string            `json:"queryFrequency"`
	QueryPeriod           string            `json:"queryPeriod"`
	TriggerOperator       string            `json:"triggerOperator"`
	TriggerThreshold      int               `json:"triggerThreshold"`
	SuppressionDuration   string            `json:"suppressionDuration"`
	SuppressionEnabled    bool              `json:"suppressionEnabled"`
	Tactics               []string          `json:"tactics"`
	Techniques            []string          `json:"techniques"`
	EntityMappings        []entityMapping   `json:"entityMappings"`
	AlertDetailsOverride  map[string]string `json:"alertDetailsOverride,omitempty"`
	EventGroupingSettings map[string]string `json:"eventGroupingSettings"`
	TemplateVersion       string            `json:"templateVersion"`
}

// isoDuration turns a rule duration (15m, 1h, 7d) into ISO 8601 (PT15M, PT1H, P7D).
func isoDuration(d string) string {
	m := duration.FindStringSubmatch(d)
	if m == nil {
		return d
	}
	if m[2] == "d" {
		return "P" + m[1] + "D"
	}
	return "PT" + m[1] + strings.ToUpper(m[2])
}

// literal keeps a string that starts with "[" from being read as an ARM expression.
func literal(s string) string {
	if strings.HasPrefix(s, "[") {
		return "[" + s
	}
	return s
}

// buildARM is sentinel/azuredeploy.json for the rules.
func buildARM(rules []rule) ([]byte, error) {
	t := armTemplate{
		Schema:         "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		ContentVersion: "1.0.0.0",
		Parameters: map[string]armParam{"workspace": {Type: "string", Metadata: map[string]string{
			"description": "The name of the Log Analytics workspace with Microsoft Sentinel, where the Altiward setup created the AltiwardOCSF_CL table",
		}}},
		Resources: []armResource{},
	}
	for _, r := range rules {
		// The API takes parent techniques only (T1136 for T1136.001).
		var techniques []string
		for _, tech := range r.RelevantTechniques {
			parent, _, _ := strings.Cut(tech, ".")
			if !slices.Contains(techniques, parent) {
				techniques = append(techniques, parent)
			}
		}
		t.Resources = append(t.Resources, armResource{
			Type:       "Microsoft.SecurityInsights/alertRules",
			APIVersion: armAPIVersion,
			Scope:      "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspace'))]",
			Name:       r.ID,
			Kind:       "Scheduled",
			Properties: armRules{
				DisplayName:           literal(r.Name),
				Description:           literal(r.Description),
				Severity:              r.Severity,
				Enabled:               true,
				Query:                 literal(r.Query),
				QueryFrequency:        isoDuration(r.QueryFrequency),
				QueryPeriod:           isoDuration(r.QueryPeriod),
				TriggerOperator:       operators[r.TriggerOperator],
				TriggerThreshold:      r.TriggerThreshold,
				SuppressionDuration:   "PT1H",
				SuppressionEnabled:    false,
				Tactics:               r.Tactics,
				Techniques:            techniques,
				EntityMappings:        r.EntityMappings,
				AlertDetailsOverride:  r.AlertDetailsOverride,
				EventGroupingSettings: map[string]string{"aggregationKind": "AlertPerResult"},
				TemplateVersion:       r.Version,
			},
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(t); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
