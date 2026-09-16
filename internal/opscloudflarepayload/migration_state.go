package opscloudflarepayload

import "errors"

const MigrationDerivationAlgorithm = "ordered-history-v1"

var allowedMigrationRemoteStates = []string{"absent", "null", "shared-known-local-tag"}

func AllowedMigrationRemoteStates() []string {
	return append([]string(nil), allowedMigrationRemoteStates...)
}

type migrationTagKind uint8

const (
	migrationTagAbsent migrationTagKind = iota
	migrationTagNull
	migrationTagValue
)

type migrationTagObservation struct {
	Kind  migrationTagKind
	Value string
}

type versionMigrationObservation struct {
	ExpectedVersionID string
	ResponseVersionID string
	RuntimePresent    bool
	Tag               migrationTagObservation
}

type migrationDecision struct {
	Omit          bool
	OldTag        string
	OldTagPresent bool
	NewTag        string
	Steps         []Migration
}

func deriveMigrationDecision(history []Migration, observations []versionMigrationObservation) (migrationDecision, error) {
	if len(history) == 0 || len(observations) == 0 {
		return migrationDecision{}, errors.New("Cloudflare migration state is incomplete")
	}
	tagIndex := make(map[string]int, len(history))
	for index, migration := range history {
		if migration.Tag == "" {
			return migrationDecision{}, errors.New("Cloudflare migration history tag is invalid")
		}
		if _, exists := tagIndex[migration.Tag]; exists {
			return migrationDecision{}, errors.New("Cloudflare migration history tag is duplicated")
		}
		tagIndex[migration.Tag] = index
	}

	remoteTag := ""
	var remoteKind migrationTagKind
	hasRemoteTag := false
	for _, observation := range observations {
		if observation.ExpectedVersionID == "" || observation.ResponseVersionID != observation.ExpectedVersionID || !observation.RuntimePresent {
			return migrationDecision{}, errors.New("Cloudflare version migration state is invalid")
		}
		var tag string
		switch observation.Tag.Kind {
		case migrationTagAbsent, migrationTagNull:
		case migrationTagValue:
			if observation.Tag.Value == "" {
				return migrationDecision{}, errors.New("Cloudflare version migration tag is invalid")
			}
			tag = observation.Tag.Value
		default:
			return migrationDecision{}, errors.New("Cloudflare version migration tag state is invalid")
		}
		if tag != "" {
			if _, known := tagIndex[tag]; !known {
				return migrationDecision{}, errors.New("Cloudflare version migration tag is unknown")
			}
		}
		if !hasRemoteTag {
			remoteKind, remoteTag, hasRemoteTag = observation.Tag.Kind, tag, true
		} else if remoteKind != observation.Tag.Kind || remoteTag != tag {
			return migrationDecision{}, errors.New("Cloudflare active versions have divergent migration tags")
		}
	}

	lastTag := history[len(history)-1].Tag
	if remoteTag == lastTag {
		return migrationDecision{Omit: true}, nil
	}
	start := 0
	decision := migrationDecision{NewTag: lastTag}
	if remoteTag != "" {
		decision.OldTag = remoteTag
		decision.OldTagPresent = true
		start = tagIndex[remoteTag] + 1
	}
	decision.Steps = append([]Migration(nil), history[start:]...)
	if len(decision.Steps) == 0 {
		return migrationDecision{}, errors.New("Cloudflare migration suffix is empty")
	}
	return decision, nil
}
