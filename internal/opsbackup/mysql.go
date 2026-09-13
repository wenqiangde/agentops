package opsbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

var safeIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var safeHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Executor interface {
	opsexec.Executor
	opsexec.PipelineExecutor
}

type BackupPlan struct {
	Service         string      `json:"service"`
	Resource        string      `json:"resource"`
	Host            string      `json:"host"`
	ServerArchive   string      `json:"server_archive"`
	LocalArchive    string      `json:"local_archive"`
	AgeRecipient    string      `json:"age_recipient"`
	ServerCopies    int         `json:"server_copies"`
	LocalCopies     int         `json:"local_copies"`
	MySQLOptionFile string      `json:"mysql_option_file"`
	Restore         RestorePlan `json:"restore"`
}

type RestorePlan struct {
	AgeIdentity       string   `json:"age_identity"`
	MySQLOptionFile   string   `json:"mysql_option_file"`
	Socket            string   `json:"socket"`
	ExpectedHostname  string   `json:"expected_hostname"`
	ExpectedPort      string   `json:"expected_port"`
	TemporaryDatabase string   `json:"temporary_database"`
	IntegrityQueries  []string `json:"integrity_queries"`
}

type BackupPreview struct {
	Version int        `json:"version"`
	Plan    BackupPlan `json:"plan"`
}

type Result struct {
	Verified        bool            `json:"verified"`
	ServerVersion   string          `json:"server_version"`
	ArchiveSize     int64           `json:"archive_size"`
	ServerSHA256    string          `json:"server_sha256"`
	LocalSHA256     string          `json:"local_sha256"`
	RestoreEvidence RestoreEvidence `json:"restore_evidence"`
}

type DatabaseIdentity struct {
	Hostname string
	Port     string
}

func Preview(ctx context.Context, _ Executor, plan BackupPlan) (BackupPreview, error) {
	if ctx == nil {
		return BackupPreview{}, errors.New("backup context is required")
	}
	if err := validatePlan(plan); err != nil {
		return BackupPreview{}, err
	}
	return BackupPreview{Version: 1, Plan: plan}, nil
}

func Digest(preview BackupPreview) (string, error) {
	if preview.Version != 1 {
		return "", errors.New("unsupported backup preview version")
	}
	data, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func Confirm(preview BackupPreview, digest string) error {
	if !sha256Pattern.MatchString(digest) {
		return errors.New("backup preview digest must be 64 lowercase hex characters")
	}
	want, err := Digest(preview)
	if err != nil || digest != want {
		return errors.New("backup preview digest is stale")
	}
	return nil
}

func Apply(ctx context.Context, executor Executor, preview BackupPreview, digest string, timeout time.Duration) (Result, error) {
	if executor == nil || timeout <= 0 {
		return Result{}, errors.New("backup executor and timeout are required")
	}
	if err := Confirm(preview, digest); err != nil {
		return Result{}, err
	}
	plan := preview.Plan
	if err := validatePlan(plan); err != nil {
		return Result{}, err
	}
	remotePartial := plan.ServerArchive + ".partial"
	localPartial := plan.LocalArchive + ".partial"
	if result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "age", Args: []string{"--version"}, Timeout: timeout}); failed(result) {
		return Result{}, errors.New("remote age availability check failed")
	}
	serverDirectory := filepath.ToSlash(filepath.Dir(plan.ServerArchive))
	if result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "mkdir", Args: []string{"-p", "--", serverDirectory}, Timeout: timeout}); failed(result) {
		return Result{}, errors.New("server backup directory creation failed")
	}
	versionResult := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "mysql", Args: []string{"--defaults-extra-file=" + plan.MySQLOptionFile, "--batch", "--skip-column-names", "--execute", "SELECT @@hostname, @@port, VERSION()"}, Timeout: timeout})
	productionIdentity, serverVersion, err := parseServerIdentity(versionResult)
	if err != nil {
		return Result{}, errors.New("database server version check failed")
	}
	dump := opsexec.PipelineRequest{HostAlias: plan.Host, Timeout: timeout, OutputPath: remotePartial, Stages: []opsexec.PipelineStage{
		{Program: "mysqldump", Args: []string{"--defaults-extra-file=" + plan.MySQLOptionFile, "--single-transaction", "--quick", plan.Resource}},
		{Program: "age", Args: []string{"-r", plan.AgeRecipient}},
	}}
	if result := executor.Pipeline(ctx, dump); failed(result) {
		return Result{}, cleanupFailure(ctx, executor, plan.Host, remotePartial, timeout, "encrypted database dump failed")
	}
	hashResult := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "sha256sum", Args: []string{"--", remotePartial}, Timeout: timeout})
	serverHash, err := parseSHA256(hashResult)
	if err != nil {
		return Result{}, cleanupFailure(ctx, executor, plan.Host, remotePartial, timeout, "server backup digest verification failed")
	}
	sizeResult := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "stat", Args: []string{"-c", "%s", "--", remotePartial}, Timeout: timeout})
	archiveSize, err := parseArchiveSize(sizeResult)
	if err != nil {
		return Result{}, cleanupFailure(ctx, executor, plan.Host, remotePartial, timeout, "server backup size verification failed")
	}
	if result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "ln", Args: []string{"--", remotePartial, plan.ServerArchive}, Timeout: timeout}); failed(result) {
		return Result{}, cleanupFailure(ctx, executor, plan.Host, remotePartial, timeout, "server backup finalization failed")
	}
	if result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "rm", Args: []string{"--", remotePartial}, Timeout: timeout}); failed(result) {
		return Result{}, errors.New("server backup partial cleanup failed")
	}
	if err := os.MkdirAll(filepath.Dir(plan.LocalArchive), 0o700); err != nil {
		return Result{}, errors.New("local backup directory creation failed")
	}
	_ = os.Remove(localPartial)
	copyResult := executor.Copy(ctx, opsexec.CopyRequest{HostAlias: plan.Host, Source: plan.ServerArchive, Destination: localPartial, Direction: opsexec.CopyFromRemote, Timeout: timeout})
	if failed(copyResult) {
		_ = os.Remove(localPartial)
		return Result{}, errors.New("encrypted backup transfer failed")
	}
	localHash, err := hashFile(localPartial)
	if err != nil || localHash != serverHash {
		_ = os.Remove(localPartial)
		return Result{ServerVersion: serverVersion, ArchiveSize: archiveSize, ServerSHA256: serverHash, LocalSHA256: localHash}, errors.New("encrypted backup transfer digest mismatch")
	}
	if err := os.Link(localPartial, plan.LocalArchive); err != nil {
		_ = os.Remove(localPartial)
		return Result{}, errors.New("local backup finalization failed")
	}
	if err := os.Remove(localPartial); err != nil {
		return Result{}, errors.New("local backup partial cleanup failed")
	}
	evidence, err := VerifyRestore(ctx, executor, plan, productionIdentity, timeout)
	if err != nil {
		return Result{ServerVersion: serverVersion, ArchiveSize: archiveSize, ServerSHA256: serverHash, LocalSHA256: localHash}, err
	}
	if err := retainVerified(ctx, executor, plan, timeout); err != nil {
		return Result{ServerVersion: serverVersion, ArchiveSize: archiveSize, ServerSHA256: serverHash, LocalSHA256: localHash, RestoreEvidence: evidence}, err
	}
	return Result{Verified: true, ServerVersion: serverVersion, ArchiveSize: archiveSize, ServerSHA256: serverHash, LocalSHA256: localHash, RestoreEvidence: evidence}, nil
}

func validatePlan(plan BackupPlan) error {
	if !safeIdentity.MatchString(plan.Service) || !safeIdentity.MatchString(plan.Resource) || !safeHost.MatchString(plan.Host) {
		return errors.New("backup identity is invalid")
	}
	if matched, _ := regexp.MatchString(`^age1[023456789acdefghjklmnpqrstuvwxyz]{58,}$`, plan.AgeRecipient); !matched {
		return errors.New("age recipient is invalid")
	}
	for _, value := range []string{plan.ServerArchive, plan.LocalArchive, plan.MySQLOptionFile} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("backup path is invalid")
		}
	}
	if plan.ServerCopies < 1 || plan.LocalCopies < 1 {
		return errors.New("backup retention is invalid")
	}
	return validateRestorePlan(plan)
}

func failed(result opsexec.Result) bool {
	return result.Err != nil || result.ExitCode != 0 || result.TimedOut
}

func parseSHA256(result opsexec.Result) (string, error) {
	if failed(result) {
		return "", errors.New("digest command failed")
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) < 1 || !sha256Pattern.MatchString(fields[0]) {
		return "", errors.New("digest output is invalid")
	}
	return fields[0], nil
}

func parseServerIdentity(result opsexec.Result) (DatabaseIdentity, string, error) {
	value := strings.TrimSpace(result.Stdout)
	fields := strings.Split(value, "\t")
	if failed(result) || len(fields) != 3 || !safeHost.MatchString(fields[0]) || fields[1] == "" || len(fields[1]) > 5 || len(fields[2]) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return DatabaseIdentity{}, "", errors.New("server identity output is invalid")
	}
	port, err := strconv.Atoi(fields[1])
	if err != nil || port < 1 || port > 65535 {
		return DatabaseIdentity{}, "", errors.New("server identity output is invalid")
	}
	return DatabaseIdentity{Hostname: fields[0], Port: fields[1]}, fields[2], nil
}

func parseArchiveSize(result opsexec.Result) (int64, error) {
	if failed(result) {
		return 0, errors.New("archive size command failed")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(result.Stdout), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("archive size output is invalid")
	}
	return value, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func cleanupRemote(_ context.Context, executor Executor, host, path string, timeout time.Duration) (opsexec.Result, error) {
	cleanupTimeout := timeout
	if cleanupTimeout > 10*time.Second {
		cleanupTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	result := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "rm", Args: []string{"--", path}, Timeout: cleanupTimeout})
	return result, result.Err
}

func cleanupFailure(ctx context.Context, executor Executor, host, archive string, timeout time.Duration, message string) error {
	result, err := cleanupRemote(ctx, executor, host, archive, timeout)
	if err != nil || failed(result) {
		return errors.New(message + "; remote partial cleanup failed")
	}
	return errors.New(message)
}

func retainVerified(ctx context.Context, executor Executor, plan BackupPlan, timeout time.Duration) error {
	directory := filepath.ToSlash(filepath.Dir(plan.ServerArchive))
	pattern := plan.Resource + "-*.sql.age"
	result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "find", Args: []string{directory, "-maxdepth", "1", "-type", "f", "-name", pattern, "-printf", "%T@ %p\\n"}, Timeout: timeout})
	if failed(result) {
		return errors.New("server backup retention listing failed")
	}
	type remoteFile struct {
		timestamp float64
		path      string
	}
	var files []remoteFile
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return errors.New("server backup retention output is invalid")
		}
		stamp, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || math.IsNaN(stamp) || math.IsInf(stamp, 0) || path.Clean(parts[1]) != parts[1] || path.Dir(parts[1]) != directory || !managedArchiveName(path.Base(parts[1]), plan.Resource) {
			return errors.New("server backup retention output is invalid")
		}
		files = append(files, remoteFile{stamp, parts[1]})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].timestamp > files[j].timestamp })
	if len(files) > plan.ServerCopies {
		for _, file := range files[plan.ServerCopies:] {
			if result := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "rm", Args: []string{"--", file.path}, Timeout: timeout}); failed(result) {
				return errors.New("server backup retention failed")
			}
		}
	}
	entries, err := os.ReadDir(filepath.Dir(plan.LocalArchive))
	if err != nil {
		return errors.New("local backup retention listing failed")
	}
	type localFile struct {
		modified time.Time
		path     string
	}
	var local []localFile
	for _, entry := range entries {
		if entry.IsDir() || !managedArchiveName(entry.Name(), plan.Resource) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("local backup retention metadata failed")
		}
		local = append(local, localFile{info.ModTime(), filepath.Join(filepath.Dir(plan.LocalArchive), entry.Name())})
	}
	sort.Slice(local, func(i, j int) bool { return local[i].modified.After(local[j].modified) })
	if len(local) > plan.LocalCopies {
		for _, file := range local[plan.LocalCopies:] {
			if err := os.Remove(file.path); err != nil {
				return errors.New("local backup retention failed")
			}
		}
	}
	return nil
}

func managedArchiveName(name, resource string) bool {
	prefix, suffix := resource+"-", ".sql.age"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	archiveID := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	return safeIdentity.MatchString(archiveID)
}
