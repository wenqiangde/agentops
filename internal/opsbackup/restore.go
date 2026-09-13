package opsbackup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

var countQueryPattern = regexp.MustCompile(`(?i)^SELECT[[:space:]]+COUNT\(\*\)[[:space:]]+FROM[[:space:]]+` + "`?" + `[A-Za-z0-9_]+` + "`?" + `$`)

type RestoreEvidence struct {
	TemporaryDatabase string `json:"temporary_database"`
	IntegrityChecks   int    `json:"integrity_checks"`
	Verified          bool   `json:"verified"`
}

func VerifyRestore(ctx context.Context, executor Executor, plan BackupPlan, production DatabaseIdentity, timeout time.Duration) (evidence RestoreEvidence, err error) {
	if executor == nil || timeout <= 0 {
		return evidence, errors.New("restore executor and timeout are required")
	}
	if err := validateRestorePlan(plan); err != nil {
		return evidence, err
	}
	restore := plan.Restore
	create := "CREATE DATABASE `" + restore.TemporaryDatabase + "`"
	drop := "DROP DATABASE `" + restore.TemporaryDatabase + "`"
	base := []string{"--defaults-extra-file=" + restore.MySQLOptionFile, "--protocol=SOCKET", "--socket=" + restore.Socket}
	identityResult := executor.Run(ctx, opsexec.Request{Program: "mysql", Args: append(append([]string{}, base...), "--batch", "--skip-column-names", "--execute", "SELECT @@hostname, @@port"), Timeout: timeout})
	restoreIdentity, err := parseRestoreIdentity(identityResult)
	expected := DatabaseIdentity{Hostname: restore.ExpectedHostname, Port: restore.ExpectedPort}
	if err != nil || restoreIdentity != expected || restoreIdentity == production {
		return evidence, errors.New("restore target is not an isolated database instance")
	}
	if result := executor.Run(ctx, opsexec.Request{Program: "mysql", Args: append(append([]string{}, base...), "--execute", create), Timeout: timeout}); failed(result) {
		return evidence, errors.New("isolated restore database creation failed")
	}
	defer func() {
		result := executor.Run(context.Background(), opsexec.Request{Program: "mysql", Args: append(append([]string{}, base...), "--execute", drop), Timeout: timeout})
		if failed(result) && err == nil {
			err = errors.New("isolated restore cleanup failed")
			evidence.Verified = false
		}
	}()
	pipeline := opsexec.PipelineRequest{InputPath: plan.LocalArchive, Timeout: timeout, Stages: []opsexec.PipelineStage{
		{Program: "age", Args: []string{"-d", "-i", restore.AgeIdentity}},
		{Program: "mysql", Args: append(append([]string{}, base...), "--database", restore.TemporaryDatabase)},
	}}
	if result := executor.Pipeline(ctx, pipeline); failed(result) {
		return evidence, errors.New("isolated restore failed")
	}
	for _, query := range restore.IntegrityQueries {
		args := append(append([]string{}, base...), "--database", restore.TemporaryDatabase, "--batch", "--skip-column-names", "--execute", query)
		if result := executor.Run(ctx, opsexec.Request{Program: "mysql", Args: args, Timeout: timeout}); failed(result) {
			return evidence, errors.New("isolated restore integrity verification failed")
		}
	}
	return RestoreEvidence{TemporaryDatabase: restore.TemporaryDatabase, IntegrityChecks: len(restore.IntegrityQueries), Verified: true}, nil
}

func parseRestoreIdentity(result opsexec.Result) (DatabaseIdentity, error) {
	identity, _, err := parseServerIdentity(opsexec.Result{ExitCode: result.ExitCode, Stdout: strings.TrimSpace(result.Stdout) + "\tlocal-restore", Stderr: result.Stderr, TimedOut: result.TimedOut, Err: result.Err})
	return identity, err
}

func validateRestorePlan(plan BackupPlan) error {
	restore := plan.Restore
	if !safeIdentity.MatchString(restore.TemporaryDatabase) || !strings.HasPrefix(restore.TemporaryDatabase, "agentsetup_restore_") || restore.TemporaryDatabase == plan.Resource {
		return errors.New("restore database must be a unique AgentSetup temporary identity")
	}
	for _, value := range []string{restore.AgeIdentity, restore.MySQLOptionFile, restore.Socket, plan.LocalArchive} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("restore path is invalid")
		}
	}
	if !safeHost.MatchString(restore.ExpectedHostname) {
		return errors.New("restore expected hostname is invalid")
	}
	port, err := strconv.Atoi(restore.ExpectedPort)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("restore expected port is invalid")
	}
	if len(restore.IntegrityQueries) == 0 {
		return errors.New("at least one restore integrity query is required")
	}
	for _, query := range restore.IntegrityQueries {
		if !countQueryPattern.MatchString(strings.TrimSpace(query)) {
			return fmt.Errorf("restore integrity query is invalid")
		}
	}
	return nil
}
