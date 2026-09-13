package opscli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsbackup"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/paths"
)

type opsBackupExecution = opsbackup.Executor

var opsBackupExecutor = func() opsBackupExecution {
	return opsbackup.NewRoutedExecutor(opsexec.NewSSHExecutor(), opsexec.NewLocalExecutor())
}

var backupArchiveID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type backupArgs struct {
	Service, ArchiveID, Recipient, RemoteOptionFile                                                  string
	RestoreIdentity, RestoreOptionFile, RestoreSocket, RestoreHostname, RestorePort, RestoreDatabase string
	IntegrityQueries                                                                                 []string
	Confirm                                                                                          bool
	Digest                                                                                           string
}

func opsBackup(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	parsed, ok := parseOpsBackupArgs(args, stderr)
	if !ok {
		return 1
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	if hasGlobalOpsIssue(issues) {
		printOpsIssues(stderr, issues)
		return 1
	}
	service, found := inv.Services[parsed.Service]
	if !found {
		selected := issuesForService(issues, parsed.Service)
		if len(selected) != 0 {
			printOpsIssues(stderr, selected)
		} else {
			fmt.Fprintf(stderr, "agentops: unknown service: %s\n", parsed.Service)
		}
		return 1
	}
	production := service.Environments[opsconfig.EnvironmentProduction]
	if production.Kind != opsconfig.EnvironmentKindSSH || service.Data.MySQL == nil {
		fmt.Fprintln(stderr, "agentops: service has no production MySQL/MariaDB backup target")
		return 1
	}
	timeout, err := time.ParseDuration(inv.Policies.Execution.DefaultTimeout)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "agentops: invalid default operation timeout")
		return 1
	}
	filename := service.Data.MySQL.Resource + "-" + parsed.ArchiveID + ".sql.age"
	plan := opsbackup.BackupPlan{
		Service: service.ID, Resource: service.Data.MySQL.Resource, Host: production.Host,
		ServerArchive: filepath.ToSlash(filepath.Join(production.Root, "shared", "backups", filename)),
		LocalArchive:  filepath.Join(p.OpsBackupRoot, service.ID, filename),
		AgeRecipient:  parsed.Recipient, ServerCopies: inv.Policies.Backups.ServerCopies, LocalCopies: inv.Policies.Backups.LocalCopies,
		MySQLOptionFile: parsed.RemoteOptionFile,
		Restore:         opsbackup.RestorePlan{AgeIdentity: parsed.RestoreIdentity, MySQLOptionFile: parsed.RestoreOptionFile, Socket: parsed.RestoreSocket, ExpectedHostname: parsed.RestoreHostname, ExpectedPort: parsed.RestorePort, TemporaryDatabase: parsed.RestoreDatabase, IntegrityQueries: parsed.IntegrityQueries},
	}
	executor := opsBackupExecutor()
	preview, err := opsbackup.Preview(context.Background(), executor, plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: backup preview is invalid")
		return 1
	}
	encoded, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: backup preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	digest, err := opsbackup.Digest(preview)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: backup preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if !parsed.Confirm {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	started := time.Now().UTC()
	result, err := opsbackup.Apply(ctx, executor, preview, parsed.Digest, timeout)
	finished := time.Now().UTC()
	status := "verified"
	errorSummary := ""
	if err != nil {
		status = "failed"
		errorSummary = "encrypted database backup or restore verification failed"
	}
	reportPath, reportErr := opsbackup.WriteReport(p.OpsReportRoot, opsbackup.Report{
		OperationID: "backup-" + parsed.ArchiveID, Service: service.ID, Resource: service.Data.MySQL.Resource, Host: production.Host, PlanDigest: digest,
		ServerVersion: result.ServerVersion, ArchiveSize: result.ArchiveSize, ServerSHA256: result.ServerSHA256, LocalSHA256: result.LocalSHA256, RestoreEvidence: result.RestoreEvidence,
		StartedAt: started, FinishedAt: finished, Status: status, Error: errorSummary,
	})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: encrypted database backup or restore verification failed")
		if reportErr == nil {
			fmt.Fprintf(stdout, "report: %s\n", reportPath)
		}
		return 1
	}
	if reportErr != nil {
		fmt.Fprintln(stderr, "agentops: backup succeeded but evidence report could not be written")
		return 1
	}
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintln(stdout, string(resultJSON))
	fmt.Fprintln(stdout, "backup: verified")
	fmt.Fprintf(stdout, "report: %s\n", reportPath)
	return 0
}

func parseOpsBackupArgs(args []string, stderr io.Writer) (backupArgs, bool) {
	var parsed backupArgs
	if len(args) < 3 || strings.HasPrefix(args[0], "-") || args[1] != "--environment" || args[2] != opsconfig.EnvironmentProduction {
		opsUsageError(stderr, "backup requires one service and --environment production")
		return parsed, false
	}
	parsed.Service = args[0]
	values := map[string]*string{
		"--archive-id": &parsed.ArchiveID, "--age-recipient": &parsed.Recipient, "--mysql-option-file": &parsed.RemoteOptionFile,
		"--restore-age-identity": &parsed.RestoreIdentity, "--restore-option-file": &parsed.RestoreOptionFile, "--restore-socket": &parsed.RestoreSocket,
		"--restore-hostname": &parsed.RestoreHostname, "--restore-port": &parsed.RestorePort, "--restore-database": &parsed.RestoreDatabase,
	}
	for index := 3; index < len(args); index++ {
		option := args[index]
		switch option {
		case "--confirm":
			if parsed.Confirm {
				return parsed, backupArgError(stderr, "duplicate --confirm")
			}
			parsed.Confirm = true
		case "--preview-digest":
			if parsed.Digest != "" || index+1 >= len(args) {
				return parsed, backupArgError(stderr, "--preview-digest requires one value")
			}
			index++
			parsed.Digest = args[index]
		case "--integrity-query":
			if index+1 >= len(args) {
				return parsed, backupArgError(stderr, "--integrity-query requires one value")
			}
			index++
			parsed.IntegrityQueries = append(parsed.IntegrityQueries, args[index])
		default:
			destination, exists := values[option]
			if !exists || *destination != "" || index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return parsed, backupArgError(stderr, "invalid or duplicate backup option: "+option)
			}
			index++
			*destination = args[index]
		}
	}
	for option, destination := range values {
		if *destination == "" {
			return parsed, backupArgError(stderr, option+" is required")
		}
	}
	if !backupArchiveID.MatchString(parsed.ArchiveID) || len(parsed.IntegrityQueries) == 0 {
		return parsed, backupArgError(stderr, "safe --archive-id and at least one --integrity-query are required")
	}
	if parsed.Confirm != (parsed.Digest != "") {
		return parsed, backupArgError(stderr, "--confirm and --preview-digest must be used together")
	}
	return parsed, true
}

func backupArgError(stderr io.Writer, message string) bool {
	opsUsageError(stderr, message)
	return false
}
