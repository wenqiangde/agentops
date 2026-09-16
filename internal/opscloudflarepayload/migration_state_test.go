package opscloudflarepayload

import (
	"reflect"
	"testing"
)

func TestDeriveMigrationDecisionFromConfirmedVersionState(t *testing.T) {
	history := []Migration{
		{Tag: "v1", NewSQLiteClasses: []string{"FirstDO"}},
		{Tag: "v2", NewSQLiteClasses: []string{"SecondDO"}},
	}
	versionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tests := []struct {
		name         string
		tag          migrationTagObservation
		wantOldTag   string
		wantOldTagOK bool
		wantTags     []string
		wantOmit     bool
	}{
		{name: "absent tag applies full history", tag: migrationTagObservation{Kind: migrationTagAbsent}, wantTags: []string{"v1", "v2"}},
		{name: "null tag applies full history", tag: migrationTagObservation{Kind: migrationTagNull}, wantTags: []string{"v1", "v2"}},
		{name: "intermediate tag applies suffix", tag: migrationTagObservation{Kind: migrationTagValue, Value: "v1"}, wantOldTag: "v1", wantOldTagOK: true, wantTags: []string{"v2"}},
		{name: "latest tag omits migrations", tag: migrationTagObservation{Kind: migrationTagValue, Value: "v2"}, wantOmit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := deriveMigrationDecision(history, []versionMigrationObservation{{
				ExpectedVersionID: versionID,
				ResponseVersionID: versionID,
				RuntimePresent:    true,
				Tag:               test.tag,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Omit != test.wantOmit || decision.OldTag != test.wantOldTag || decision.OldTagPresent != test.wantOldTagOK || !reflect.DeepEqual(migrationTags(decision.Steps), test.wantTags) {
				t.Fatalf("decision=%+v", decision)
			}
			if !test.wantOmit && decision.NewTag != "v2" {
				t.Fatalf("new tag=%q", decision.NewTag)
			}
		})
	}
}

func TestDeriveMigrationDecisionRejectsUntrustedOrDivergentState(t *testing.T) {
	validHistory := []Migration{
		{Tag: "v1", NewSQLiteClasses: []string{"FirstDO"}},
		{Tag: "v2", NewSQLiteClasses: []string{"SecondDO"}},
	}
	firstID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	secondID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	valid := versionMigrationObservation{
		ExpectedVersionID: firstID,
		ResponseVersionID: firstID,
		RuntimePresent:    true,
		Tag:               migrationTagObservation{Kind: migrationTagValue, Value: "v1"},
	}
	tests := []struct {
		name         string
		history      []Migration
		observations []versionMigrationObservation
	}{
		{name: "empty string tag", history: validHistory, observations: []versionMigrationObservation{{ExpectedVersionID: firstID, ResponseVersionID: firstID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagValue}}}},
		{name: "unknown tag", history: validHistory, observations: []versionMigrationObservation{{ExpectedVersionID: firstID, ResponseVersionID: firstID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagValue, Value: "v9"}}}},
		{name: "duplicate local tag", history: []Migration{{Tag: "v1"}, {Tag: "v1"}}, observations: []versionMigrationObservation{valid}},
		{name: "missing runtime", history: validHistory, observations: []versionMigrationObservation{{ExpectedVersionID: firstID, ResponseVersionID: firstID, Tag: migrationTagObservation{Kind: migrationTagValue, Value: "v1"}}}},
		{name: "response version mismatch", history: validHistory, observations: []versionMigrationObservation{{ExpectedVersionID: firstID, ResponseVersionID: secondID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagValue, Value: "v1"}}}},
		{name: "split traffic tag divergence", history: validHistory, observations: []versionMigrationObservation{valid, {ExpectedVersionID: secondID, ResponseVersionID: secondID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagValue, Value: "v2"}}}},
		{name: "split traffic absent null divergence", history: validHistory, observations: []versionMigrationObservation{
			{ExpectedVersionID: firstID, ResponseVersionID: firstID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagAbsent}},
			{ExpectedVersionID: secondID, ResponseVersionID: secondID, RuntimePresent: true, Tag: migrationTagObservation{Kind: migrationTagNull}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if decision, err := deriveMigrationDecision(test.history, test.observations); err == nil {
				t.Fatalf("unsafe migration state accepted: %+v", decision)
			}
		})
	}
}

func migrationTags(migrations []Migration) []string {
	if migrations == nil {
		return nil
	}
	tags := make([]string, len(migrations))
	for index, migration := range migrations {
		tags[index] = migration.Tag
	}
	return tags
}
