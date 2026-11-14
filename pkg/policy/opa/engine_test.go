/*
    Copyright (C) 2022 Tenable, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package opa

import (
	"path/filepath"
	"testing"

	"github.com/tenable/terrascan/pkg/filters"
	"github.com/tenable/terrascan/pkg/iac-providers/output"
	"github.com/tenable/terrascan/pkg/policy"
)

const (
	severityFilterPolicyPath = "testdata/severity_filter"
	severityTestResourceType = "severity_test_resource"

	lowRuleID    = "AC_TEST_LOW_0001"
	mediumRuleID = "AC_TEST_MEDIUM_0001"
	highRuleID   = "AC_TEST_HIGH_0001"
)

// newSeverityTestEngine initialises an OPA engine with the three fixed
// LOW/MEDIUM/HIGH test rules and the given --severity threshold.
func newSeverityTestEngine(t *testing.T, severity string) *Engine {
	t.Helper()

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	absPolicyPath, err := filepath.Abs(severityFilterPolicyPath)
	if err != nil {
		t.Fatalf("failed to get abs policy path: %v", err)
	}

	preloadFilter := filters.NewRegoMetadataPreLoadFilter(nil, nil, nil, nil, severity)
	if err := engine.Init(absPolicyPath, preloadFilter); err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}
	return engine
}

func severityTestInput(resources ...output.ResourceConfig) policy.EngineInput {
	return policy.EngineInput{
		InputData: &output.AllResourceConfigs{
			severityTestResourceType: resources,
		},
	}
}

func severityTestResource(id, minSeverity, maxSeverity string) output.ResourceConfig {
	return output.ResourceConfig{
		// FindAllResourcesByID derives the resource type from the second to
		// last dot separated segment of the id, so the id is namespaced with
		// the resource type like a real terraform resource id.
		ID:          severityTestResourceType + "." + id,
		Name:        id,
		Type:        severityTestResourceType,
		Config:      map[string]interface{}{"violate": true},
		MinSeverity: minSeverity,
		MaxSeverity: maxSeverity,
	}
}

// severityCount counts reported violations by their effective severity.
func severityCount(t *testing.T, store policy.EngineOutput) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, v := range store.ViolationStore.Violations {
		counts[v.Severity]++
	}
	return counts
}

func ruleIDs(store policy.EngineOutput) map[string]bool {
	ids := map[string]bool{}
	for _, v := range store.ViolationStore.Violations {
		ids[v.RuleID] = true
	}
	return ids
}

// TestEngineSeverityThresholdAppliedAfterResourceOverrides verifies that the
// --severity threshold is decided against each violation's effective severity,
// i.e. after the resource level #ts:minseverity / #ts:maxseverity overrides.
func TestEngineSeverityThresholdAppliedAfterResourceOverrides(t *testing.T) {
	tests := []struct {
		name string
		// severity is the --severity flag value, empty means no threshold
		severity        string
		resource        output.ResourceConfig
		wantViolations  map[string]bool
		wantSeverity    map[string]int
		wantHigh        int
		wantMedium      int
		wantLow         int
		wantViolated    int
		wantSkipped     int
		wantTotalPolicy int
	}{
		{
			// baseline: a resource without any severity annotation reports all
			// three violations with their rule defined severities
			name:            "no annotation and no severity threshold reports all violations",
			severity:        "",
			resource:        severityTestResource("plain", "", ""),
			wantViolations:  map[string]bool{lowRuleID: true, mediumRuleID: true, highRuleID: true},
			wantSeverity:    map[string]int{"LOW": 1, "MEDIUM": 1, "HIGH": 1},
			wantHigh:        1,
			wantMedium:      1,
			wantLow:         1,
			wantViolated:    3,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// plain resource under a high threshold keeps only the HIGH rule
			name:            "no annotation with high threshold reports only high violations",
			severity:        "HIGH",
			resource:        severityTestResource("plain", "", ""),
			wantViolations:  map[string]bool{highRuleID: true},
			wantSeverity:    map[string]int{"HIGH": 1},
			wantHigh:        1,
			wantMedium:      0,
			wantLow:         0,
			wantViolated:    1,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// combination 1: a MEDIUM rule lifted to HIGH by minseverity=High
			// must be reported under --severity high and counted as HIGH
			name:           "minseverity High lifts medium and low rules above the high threshold",
			severity:       "HIGH",
			resource:       severityTestResource("min-high", "High", ""),
			wantViolations: map[string]bool{lowRuleID: true, mediumRuleID: true, highRuleID: true},
			wantSeverity:   map[string]int{"HIGH": 3},
			wantHigh:       3,
			wantMedium:     0,
			wantLow:        0,
			wantViolated:   3,
			wantSkipped:    0,
			// all rules are still loaded and evaluated even with a high threshold
			wantTotalPolicy: 3,
		},
		{
			// without a threshold the same resource still reports everything,
			// now all at effective HIGH, matching the no-threshold behaviour
			name:            "minseverity High without threshold reports all violations as high",
			severity:        "",
			resource:        severityTestResource("min-high", "High", ""),
			wantViolations:  map[string]bool{lowRuleID: true, mediumRuleID: true, highRuleID: true},
			wantSeverity:    map[string]int{"HIGH": 3},
			wantHigh:        3,
			wantMedium:      0,
			wantLow:         0,
			wantViolated:    3,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// combination 2: HIGH and MEDIUM rules pushed down to LOW by
			// maxseverity=Low must NOT be reported under --severity high
			name:            "maxseverity Low pushes violations below the high threshold",
			severity:        "HIGH",
			resource:        severityTestResource("max-low", "", "Low"),
			wantViolations:  map[string]bool{},
			wantSeverity:    map[string]int{},
			wantHigh:        0,
			wantMedium:      0,
			wantLow:         0,
			wantViolated:    0,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// the same resource without a threshold reports all three as LOW
			name:            "maxseverity Low without threshold reports all violations as low",
			severity:        "",
			resource:        severityTestResource("max-low", "", "Low"),
			wantViolations:  map[string]bool{lowRuleID: true, mediumRuleID: true, highRuleID: true},
			wantSeverity:    map[string]int{"LOW": 3},
			wantHigh:        0,
			wantMedium:      0,
			wantLow:         3,
			wantViolated:    3,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// a medium threshold on the capped resource reports nothing either
			name:            "maxseverity Low with medium threshold reports no violations",
			severity:        "MEDIUM",
			resource:        severityTestResource("max-low", "", "Low"),
			wantViolations:  map[string]bool{},
			wantSeverity:    map[string]int{},
			wantHigh:        0,
			wantMedium:      0,
			wantLow:         0,
			wantViolated:    0,
			wantSkipped:     0,
			wantTotalPolicy: 3,
		},
		{
			// maxseverity=None keeps its skip semantics regardless of the
			// threshold: violations land in skipped_violations, nothing is
			// reported and no summary counters move
			name:            "maxseverity None skips all violations even under high threshold",
			severity:        "HIGH",
			resource:        severityTestResource("max-none", "", "None"),
			wantViolations:  map[string]bool{},
			wantSeverity:    map[string]int{},
			wantHigh:        0,
			wantMedium:      0,
			wantLow:         0,
			wantViolated:    0,
			wantSkipped:     3,
			wantTotalPolicy: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newSeverityTestEngine(t, tt.severity)

			got, err := engine.Evaluate(severityTestInput(tt.resource), &filters.RegoDataFilter{})
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if got.ViolationStore == nil {
				t.Fatal("expected a violation store in engine output")
			}

			if len(got.Violations) != len(tt.wantViolations) {
				t.Errorf("violation count = %d, want %d; violations: %v",
					len(got.Violations), len(tt.wantViolations), got.Violations)
			}

			gotIDs := ruleIDs(got)
			if len(gotIDs) != len(tt.wantViolations) {
				t.Errorf("violated rule ids = %v, want %v", gotIDs, tt.wantViolations)
			}
			for id := range tt.wantViolations {
				if !gotIDs[id] {
					t.Errorf("expected violation for rule %s to be reported, got %v", id, gotIDs)
				}
			}

			gotSeverity := severityCount(t, got)
			if len(gotSeverity) != len(tt.wantSeverity) {
				t.Errorf("severity distribution = %v, want %v", gotSeverity, tt.wantSeverity)
			}
			for level, count := range tt.wantSeverity {
				if gotSeverity[level] != count {
					t.Errorf("severity %s count = %d, want %d (full distribution: %v)",
						level, gotSeverity[level], count, gotSeverity)
				}
			}

			summary := got.Summary
			if summary.HighCount != tt.wantHigh || summary.MediumCount != tt.wantMedium ||
				summary.LowCount != tt.wantLow || summary.ViolatedPolicies != tt.wantViolated {
				t.Errorf("scan_summary mismatch: got {high:%d medium:%d low:%d violated:%d}, want {high:%d medium:%d low:%d violated:%d}",
					summary.HighCount, summary.MediumCount, summary.LowCount, summary.ViolatedPolicies,
					tt.wantHigh, tt.wantMedium, tt.wantLow, tt.wantViolated)
			}

			if len(got.SkippedViolations) != tt.wantSkipped {
				t.Errorf("skipped violations = %d, want %d", len(got.SkippedViolations), tt.wantSkipped)
			}

			if summary.TotalPolicies != tt.wantTotalPolicy {
				t.Errorf("policies_validated = %d, want %d", summary.TotalPolicies, tt.wantTotalPolicy)
			}
		})
	}
}

// TestEngineMixedAnnotatedAndPlainResources makes sure resources without
// annotations keep their original behaviour when scanned together with
// annotated resources under a severity threshold.
func TestEngineMixedAnnotatedAndPlainResources(t *testing.T) {
	engine := newSeverityTestEngine(t, "HIGH")

	plain := severityTestResource("plain-resource", "", "")
	minHigh := severityTestResource("min-high-resource", "High", "")
	maxLow := severityTestResource("max-low-resource", "", "Low")

	got, err := engine.Evaluate(severityTestInput(plain, minHigh, maxLow), &filters.RegoDataFilter{})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// plain resource: only the native HIGH rule survives
	// min-high resource: all three rules are lifted to HIGH and survive
	// max-low resource: everything is capped to LOW and is filtered out
	if len(got.Violations) != 4 {
		t.Fatalf("expected 4 reported violations, got %d: %v", len(got.Violations), got.Violations)
	}
	if got.Summary.HighCount != 4 || got.Summary.MediumCount != 0 || got.Summary.LowCount != 0 {
		t.Errorf("unexpected summary: %+v", got.Summary)
	}
	if got.Summary.ViolatedPolicies != 4 {
		t.Errorf("violated_policies = %d, want 4", got.Summary.ViolatedPolicies)
	}

	reportedResources := map[string]int{}
	for _, v := range got.Violations {
		if v.Severity != "HIGH" {
			t.Errorf("violation for %s has severity %s, want HIGH", v.ResourceName, v.Severity)
		}
		reportedResources[v.ResourceName]++
	}
	if reportedResources["plain-resource"] != 1 {
		t.Errorf("plain resource expected 1 violation, got %d", reportedResources["plain-resource"])
	}
	if reportedResources["min-high-resource"] != 3 {
		t.Errorf("min-high resource expected 3 violations, got %d", reportedResources["min-high-resource"])
	}
	if reportedResources["max-low-resource"] != 0 {
		t.Errorf("max-low resource expected 0 violations, got %d", reportedResources["max-low-resource"])
	}
}

// TestPreLoadFilterStillLoadsAllSeverities verifies the pre load filter no
// longer drops rules based on the rule metadata severity.
func TestPreLoadFilterStillLoadsAllSeverities(t *testing.T) {
	engine := newSeverityTestEngine(t, "HIGH")
	if len(engine.regoDataMap) != 3 {
		t.Errorf("expected all 3 rules to be loaded under a high threshold, got %d", len(engine.regoDataMap))
	}
}
