package opsdeploy_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsartifact"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsdeploy"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type recordingExecutor struct {
	requests       []opsexec.Request
	copies         []opsexec.CopyRequest
	currentMissing bool
	overrides      map[string]opsexec.Result
}

func (e *recordingExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, request)
	if result, ok := e.overrides[request.Program]; ok {
		return result
	}
	switch request.Program {
	case "test":
		if e.currentMissing {
			return opsexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}
		}
		return opsexec.Result{ExitCode: 0}
	case "readlink":
		return opsexec.Result{ExitCode: 0, Stdout: "/opt/apps/demo/releases/1.0.0\n"}
	case "id":
		return opsexec.Result{ExitCode: 0, Stdout: "deploy\n"}
	case "uname":
		return opsexec.Result{ExitCode: 0, Stdout: "Linux x86_64\n"}
	case "df":
		return opsexec.Result{ExitCode: 0, Stdout: "1048576\n"}
	case "which":
		return opsexec.Result{ExitCode: 0, Stdout: "/usr/bin/" + request.Args[0] + "\n"}
	case "systemctl":
		return opsexec.Result{ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\n"}
	case "sha256sum":
		return opsexec.Result{ExitCode: 0, Stdout: strings.Repeat("c", 64) + "  /opt/apps/demo/shared/config/app.env\n"}
	case "curl":
		return opsexec.Result{ExitCode: 0, Stdout: "200"}
	default:
		return opsexec.Result{ExitCode: 99, Err: errors.New("unexpected command")}
	}
}
func (e *recordingExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	e.copies = append(e.copies, request)
	return opsexec.Result{ExitCode: 99, Err: errors.New("copy must not run")}
}

func TestPlanDigestCanonicalizesSemanticSetsAndTracksMaterialInputs(t *testing.T) {
	base := samplePlan()
	reordered := samplePlan()
	reordered.HostCapabilities = []string{"systemd", "curl"}
	reordered.Health.SuccessStatuses = []int{204, 200}
	reordered.Preflight.RequiredCommands = []opsdeploy.CommandEvidence{{Name: "tar", Available: true}, {Name: "mkdir", Available: true}}
	reordered.ConfigFingerprints = map[string]string{"shared/config/z.env": strings.Repeat("d", 64), "shared/config/app.env": strings.Repeat("c", 64)}
	baseDigest := mustDigest(t, base)
	if got := mustDigest(t, reordered); got != baseDigest {
		t.Fatalf("semantic reorder changed digest")
	}
	duplicated := samplePlan()
	duplicated.HostCapabilities = []string{"curl", "systemd", "curl"}
	if got := mustDigest(t, duplicated); got != baseDigest {
		t.Fatalf("duplicate semantic capability changed digest")
	}
	cases := map[string]func(*opsdeploy.Plan){
		"version":         func(p *opsdeploy.Plan) { p.Version = "2.0.0" },
		"artifact":        func(p *opsdeploy.Plan) { p.ArtifactSHA256 = strings.Repeat("b", 64) },
		"artifact commit": func(p *opsdeploy.Plan) { p.ArtifactCommit = "new" },
		"artifact target": func(p *opsdeploy.Plan) { p.ArtifactArchitecture = "arm64" },
		"artifact size":   func(p *opsdeploy.Plan) { p.ArtifactSize++ },
		"expanded size":   func(p *opsdeploy.Plan) { p.ArtifactExpandedSize++ },
		"required disk":   func(p *opsdeploy.Plan) { p.RequiredDiskBytes++ },
		"current":         func(p *opsdeploy.Plan) { p.CurrentVersion = "0.9.0" },
		"config content":  func(p *opsdeploy.Plan) { p.ConfigFingerprints["shared/config/app.env"] = strings.Repeat("e", 64) },
		"migration":       func(p *opsdeploy.Plan) { p.Migration.Command = "./new-migrate" },
		"health":          func(p *opsdeploy.Plan) { p.Health.URL = "http://127.0.0.1:9090/health" },
		"host":            func(p *opsdeploy.Plan) { p.HostArchitecture = "arm64" },
		"policy":          func(p *opsdeploy.Plan) { p.Policy.ReleaseRetain++ },
		"preflight":       func(p *opsdeploy.Plan) { p.Preflight.DiskAvailableBytes++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := samplePlan()
			mutate(&changed)
			if mustDigest(t, changed) == baseDigest {
				t.Fatalf("%s did not affect digest", name)
			}
		})
	}
}

func TestCreateRejectsUnknownRunnerStateAndInsufficientExpandedDisk(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	if _, err := opsdeploy.Create(context.Background(), &recordingExecutor{overrides: map[string]opsexec.Result{"systemctl": {ExitCode: 0, Stdout: ""}}}, service, host, policies, artifact, time.Second); err == nil {
		t.Fatal("unknown runner state was accepted")
	}
	artifact.ExpandedSize = 1048575
	if _, err := opsdeploy.Create(context.Background(), &recordingExecutor{}, service, host, policies, artifact, time.Second); err == nil {
		t.Fatal("insufficient expanded disk was accepted")
	}
}

func TestCreateParsesConfigDigestForPathWithSpacesAndBackslashes(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	environment := service.Environments[opsconfig.EnvironmentProduction]
	environment.Config.Files = []string{`shared/config/app file\\name.env`}
	service.Environments[opsconfig.EnvironmentProduction] = environment
	executor := &recordingExecutor{overrides: map[string]opsexec.Result{"sha256sum": {ExitCode: 0, Stdout: `\` + strings.Repeat("c", 64) + `  /opt/apps/demo/shared/config/app file\\\\name.env` + "\n"}}}
	plan, err := opsdeploy.Create(context.Background(), executor, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ConfigFingerprints[`shared/config/app file\\name.env`] != strings.Repeat("c", 64) {
		t.Fatalf("fingerprints=%v", plan.ConfigFingerprints)
	}
}

func TestCreateBuildsCompleteOrderedFutureTraceAndRecovery(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	executor := &recordingExecutor{}
	plan, err := opsdeploy.Create(context.Background(), executor, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"verify-local-artifact-before-copy", "create-temporary-directory", "upload-artifact", "verify-local-artifact-after-copy", "verify-remote-sha256", "revalidate-preflight", "inspect-release-target", "inspect-existing-release-marker", "verify-existing-release", "create-release-directory", "extract-artifact", "record-release-artifact", "seal-release", "create-previous-temporary-link", "create-current-temporary-link", "rename-previous-link", "rename-current-link", "restart-runner", "process-health", "application-health", "write-local-report", "prune-releases"}
	if got := stepKinds(plan.Steps); !reflect.DeepEqual(got, want) {
		t.Fatalf("steps=%v want=%v", got, want)
	}
	for i, step := range plan.Steps {
		if step.Order != i+1 || step.Scope == "" || step.Access == "" || step.Condition == "" {
			t.Fatalf("step=%+v", step)
		}
	}
	if !plan.Recovery.Ready || len(plan.Recovery.Steps) != 6 {
		t.Fatalf("recovery=%+v", plan.Recovery)
	}
	if len(executor.copies) != 0 || hasWriteRequest(executor.requests) {
		t.Fatalf("preview wrote: %+v", executor.requests)
	}
	if plan.Preflight.RemoteUser != "deploy" || plan.Preflight.OS != "linux" || plan.Preflight.Architecture != "amd64" || !plan.Preflight.Runner.Identified || !plan.Preflight.Health.Executable {
		t.Fatalf("preflight=%+v", plan.Preflight)
	}
}

func TestCreateSupportsPHPFPMWithExactDeploymentAndRecoveryCommands(t *testing.T) {
	service, host, policies, artifact := phpFPMInputs()
	plan, err := opsdeploy.Create(context.Background(), &recordingExecutor{overrides: map[string]opsexec.Result{
		"systemctl": {ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\nFragmentPath=/usr/lib/systemd/system/php8.5-fpm.service\n"},
	}}, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Blocked || !plan.Recovery.Ready {
		t.Fatalf("plan blocked=%v reason=%q recovery=%+v", plan.Blocked, plan.BlockReason, plan.Recovery)
	}
	wantDeploy := []opsdeploy.Step{
		{Kind: "verify-runner-metadata", Program: "systemctl", Args: []string{"show", "php8.5-fpm", "--property=ActiveState,SubState,MainPID,FragmentPath", "--no-pager"}},
		{Kind: "verify-runner-config-owner", Program: "stat", Args: []string{"-c", "%F %U", "--", "/usr/lib/systemd/system/php8.5-fpm.service"}},
		{Kind: "activate-runner", Program: "systemctl", Args: []string{"reload", "php8.5-fpm"}},
		{Kind: "process-health-metadata", Program: "systemctl", Args: []string{"show", "php8.5-fpm", "--property=ActiveState,SubState,MainPID,FragmentPath", "--no-pager"}},
		{Kind: "process-health-config-owner", Program: "stat", Args: []string{"-c", "%F %U", "--", "/usr/lib/systemd/system/php8.5-fpm.service"}},
	}
	assertOrderedStepCommands(t, plan.Steps, wantDeploy)
	wantRecovery := []opsdeploy.Step{
		{Kind: "verify-previous-runner-metadata", Program: "systemctl", Args: wantDeploy[0].Args},
		{Kind: "verify-previous-runner-config-owner", Program: "stat", Args: wantDeploy[1].Args},
		{Kind: "activate-previous-runner", Program: "systemctl", Args: wantDeploy[2].Args},
		{Kind: "verify-previous-process-metadata", Program: "systemctl", Args: wantDeploy[3].Args},
		{Kind: "verify-previous-process-config-owner", Program: "stat", Args: wantDeploy[4].Args},
	}
	assertOrderedStepCommands(t, plan.Recovery.Steps, wantRecovery)
	if plan.Preflight.Runner.ConfigOwner != "root" || plan.Preflight.Runner.ConfigPath != "/usr/lib/systemd/system/php8.5-fpm.service" {
		t.Fatalf("runner evidence=%+v", plan.Preflight.Runner)
	}
}

func TestPlanDigestTracksPHPFPMIdentityOwnerAndConfigPath(t *testing.T) {
	service, host, policies, artifact := phpFPMInputs()
	build := func(service opsconfig.Service) opsdeploy.Plan {
		plan, err := opsdeploy.Create(context.Background(), &recordingExecutor{overrides: map[string]opsexec.Result{
			"systemctl": {ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\n"},
		}}, service, host, policies, artifact, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	base := build(service)
	baseDigest := mustDigest(t, base)
	for name, mutate := range map[string]func(*opsconfig.Environment){
		"service":     func(env *opsconfig.Environment) { env.Service = "php8.6-fpm" },
		"configOwner": func(env *opsconfig.Environment) { env.ConfigOwner = "www-data" },
		"configPath":  func(env *opsconfig.Environment) { env.ConfigPath = "/usr/lib/systemd/system/php8.6-fpm.service" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := service
			changed.Environments = map[string]opsconfig.Environment{}
			for key, value := range service.Environments {
				changed.Environments[key] = value
			}
			env := changed.Environments[opsconfig.EnvironmentProduction]
			mutate(&env)
			changed.Environments[opsconfig.EnvironmentProduction] = env
			if got := mustDigest(t, build(changed)); got == baseDigest {
				t.Fatalf("%s did not affect digest", name)
			}
		})
	}
}

func TestCreateSupportsFirstDeploymentWithoutRollback(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	plan, err := opsdeploy.Create(context.Background(), &recordingExecutor{currentMissing: true}, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CurrentVersion != "" || plan.Recovery.Ready || strings.Contains(strings.Join(stepKinds(plan.Steps), ","), "previous") {
		t.Fatalf("plan=%+v", plan)
	}
	if !strings.Contains(plan.Recovery.Reason, "first deployment") {
		t.Fatalf("recovery=%+v", plan.Recovery)
	}
}

func TestCreateFailsClosedWhenCurrentInspectionTransportFails(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	executor := &recordingExecutor{overrides: map[string]opsexec.Result{"test": {ExitCode: 255, Err: errors.New("transport failed")}}}
	if _, err := opsdeploy.Create(context.Background(), executor, service, host, policies, artifact, time.Second); err == nil {
		t.Fatal("transport failure was treated as first deployment")
	}
}

func TestCreateFailsClosedOnPreflightMismatchFailureAndTimeout(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	tests := []struct {
		name string
		exec *recordingExecutor
	}{
		{"platform mismatch", &recordingExecutor{overrides: map[string]opsexec.Result{"uname": {ExitCode: 0, Stdout: "Darwin arm64\n"}}}},
		{"read failure", &recordingExecutor{overrides: map[string]opsexec.Result{"id": {ExitCode: 7, Stdout: "token=secret", Err: errors.New("secret")}}}},
		{"timeout", &recordingExecutor{overrides: map[string]opsexec.Result{"df": {ExitCode: -1, TimedOut: true, Err: context.DeadlineExceeded}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opsdeploy.Create(context.Background(), tt.exec, service, host, policies, artifact, time.Second)
			if err == nil || strings.Contains(err.Error(), "secret") || len(tt.exec.copies) != 0 || hasWriteRequest(tt.exec.requests) {
				t.Fatalf("err=%v requests=%+v", err, tt.exec.requests)
			}
		})
	}
}

func TestCreateUsesRemoteContentDigestsAndRecordsUnhealthyEvidence(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	executor := &recordingExecutor{overrides: map[string]opsexec.Result{"curl": {ExitCode: 0, Stdout: "503"}}}
	plan, err := opsdeploy.Create(context.Background(), executor, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ConfigFingerprints["shared/config/app.env"] != strings.Repeat("c", 64) || plan.Preflight.Health.Healthy || !plan.Preflight.Health.Executable {
		t.Fatalf("plan=%+v", plan)
	}
	for _, request := range executor.requests {
		if request.Program == "sha256sum" && (len(request.Args) != 2 || request.Args[0] != "--") {
			t.Fatalf("unsafe request=%+v", request)
		}
	}
}

func TestCreateParsesGNUDFHeaderAndRejectsExtraFields(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	plan, err := opsdeploy.Create(context.Background(), &recordingExecutor{overrides: map[string]opsexec.Result{"df": {ExitCode: 0, Stdout: "   Avail\n1048576\n"}}}, service, host, policies, artifact, time.Second)
	if err != nil || plan.Preflight.DiskAvailableBytes != 1048576 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err := opsdeploy.Create(context.Background(), &recordingExecutor{overrides: map[string]opsexec.Result{"df": {ExitCode: 0, Stdout: "Avail\n1048576 unexpected\n"}}}, service, host, policies, artifact, time.Second); err == nil {
		t.Fatal("malformed df output was accepted")
	}
}

func TestMarshalPreviewRedactsSensitiveCommandMaterial(t *testing.T) {
	plan := samplePlan()
	plan.Health.URL = "https://user:password@example.com/health?token=secret#private"
	plan.Health.Command = &opsconfig.CommandProbe{Program: "check", Args: []string{"--token", "secret"}}
	plan.Migration.Command = "./migrate --password secret"
	plan.Steps[0].Args = []string{"--token", "secret"}
	data, err := opsdeploy.MarshalPreview(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"password", "token", "secret", "#private", "user:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("leaked %q: %s", forbidden, text)
		}
	}
	for _, required := range []string{"https://example.com/health", "arg_count", "command_digest"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %q: %s", required, text)
		}
	}
	for _, required := range []string{"migration-command", "/opt/apps/demo/releases/1.1.0", "/opt/apps/demo/current", "/opt/apps/demo/previous", "demo.service"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing reviewable target %q: %s", required, text)
		}
	}
}

func TestMarshalPreviewRedactsEnvironmentPrefixedMigrationStep(t *testing.T) {
	plan := samplePlan()
	secret := "private-value"
	command := "TOKEN=" + secret + " ./migrate --password " + secret
	plan.Migration.Command = command
	plan.Steps = append(plan.Steps, opsdeploy.Step{Order: 2, Kind: "run-migration", Scope: "remote", Access: opsdeploy.AccessWrite, Condition: "after-backup", Program: command})
	data, err := opsdeploy.MarshalPreview(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, secret) || strings.Contains(text, "TOKEN=") || strings.Contains(text, "password") || strings.Count(text, "migration-command") != 2 {
		t.Fatalf("unsafe migration preview: %s", text)
	}
}

func TestMarshalPreviewDeduplicatesHostCapabilities(t *testing.T) {
	plan := samplePlan()
	plan.HostCapabilities = []string{"systemd", "curl", "curl"}
	data, err := opsdeploy.MarshalPreview(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"curl"`) != 1 {
		t.Fatalf("capabilities were not deduplicated: %s", data)
	}
}

func TestMarshalPreviewUsesSnakeCaseKeysAtEveryLevel(t *testing.T) {
	data, err := opsdeploy.MarshalPreview(samplePlan())
	if err != nil {
		t.Fatal(err)
	}

	var preview any
	if err := json.Unmarshal(data, &preview); err != nil {
		t.Fatal(err)
	}
	assertSnakeCaseJSONKeys(t, preview, "preview")
}

var snakeCaseJSONKey = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

func assertSnakeCaseJSONKeys(t *testing.T, value any, location string) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if location != "preview.config_fingerprints" && !snakeCaseJSONKey.MatchString(key) {
				t.Errorf("%s contains non-snake_case JSON key %q", location, key)
			}
			assertSnakeCaseJSONKeys(t, child, location+"."+key)
		}
	case []any:
		for _, child := range value {
			assertSnakeCaseJSONKeys(t, child, location+"[]")
		}
	}
}

func TestMigrationWithoutCompatibilityEvidenceIsBlocked(t *testing.T) {
	service, host, policies, artifact := sampleInputs()
	service.Data.MySQL = &opsconfig.MySQLData{Resource: "primary", MigrationCommand: "./migrate --password secret", BackupPolicy: "before-migration"}
	plan, err := opsdeploy.Create(context.Background(), &recordingExecutor{}, service, host, policies, artifact, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Blocked || plan.Recovery.Ready || opsdeploy.Confirm(plan, mustDigest(t, plan)) == nil {
		t.Fatalf("plan=%+v", plan)
	}
}

func sampleInputs() (opsconfig.Service, opsconfig.Host, opsconfig.Policies, opsartifact.Verified) {
	service := opsconfig.Service{ID: "demo", Environments: map[string]opsconfig.Environment{opsconfig.EnvironmentProduction: {
		Kind: opsconfig.EnvironmentKindSSH, Host: "prod", Root: "/opt/apps/demo", Runner: opsconfig.RunnerSystemd, Unit: "demo.service",
		Config: opsconfig.ConfigContract{Files: []string{"shared/config/app.env"}},
		Health: opsconfig.Health{Type: "http", URL: "http://127.0.0.1:8080/health", SuccessStatuses: []int{200, 204}},
	}}}
	host := opsconfig.Host{SSHAlias: "prod-demo", Platform: "ubuntu", Architecture: "amd64", Capabilities: []string{"curl", "systemd"}}
	policies := opsconfig.Policies{Execution: opsconfig.ExecutionPolicies{DefaultTimeout: "30s", HealthTimeout: "10s", BatchConcurrency: 1}, Production: opsconfig.ProductionPolicies{RequirePreviewDigest: true, RequireCleanArtifactManifest: true}, Releases: opsconfig.ReleasePolicies{Retain: 3}}
	artifact := opsartifact.Verified{Manifest: opsartifact.Manifest{Service: "demo", Version: "1.1.0", Commit: "abcdef", Platform: "linux", Architecture: "amd64", SHA256: strings.Repeat("a", 64)}, ArchivePath: "/tmp/demo.tar.gz", Size: 7, ExpandedSize: 9, SHA256: strings.Repeat("a", 64)}
	return service, host, policies, artifact
}

func phpFPMInputs() (opsconfig.Service, opsconfig.Host, opsconfig.Policies, opsartifact.Verified) {
	service, host, policies, artifact := sampleInputs()
	env := service.Environments[opsconfig.EnvironmentProduction]
	env.Runner = opsconfig.RunnerPHPFPM
	env.Unit = ""
	env.Service = "php8.5-fpm"
	env.ConfigOwner = "root"
	env.ConfigPath = "/usr/lib/systemd/system/php8.5-fpm.service"
	service.Environments[opsconfig.EnvironmentProduction] = env
	host.Capabilities = []string{"curl", "php-fpm"}
	return service, host, policies, artifact
}

func samplePlan() opsdeploy.Plan {
	service, host, policies, artifact := sampleInputs()
	return opsdeploy.Plan{
		Service: service.ID, Environment: opsconfig.EnvironmentProduction, Host: host.SSHAlias, DeploymentRoot: "/opt/apps/demo", HostPlatform: host.Platform, HostArchitecture: host.Architecture, HostCapabilities: []string{"curl", "systemd"},
		Version: artifact.Manifest.Version, ArtifactSHA256: artifact.SHA256, ArtifactCommit: artifact.Manifest.Commit, ArtifactPlatform: artifact.Manifest.Platform, ArtifactArchitecture: artifact.Manifest.Architecture, ArtifactSize: artifact.Size, ArtifactExpandedSize: artifact.ExpandedSize, RequiredDiskBytes: artifact.Size + artifact.ExpandedSize,
		CurrentVersion: "1.0.0", ConfigFingerprints: map[string]string{"shared/config/app.env": strings.Repeat("c", 64), "shared/config/z.env": strings.Repeat("d", 64)},
		Health: service.Environments[opsconfig.EnvironmentProduction].Health, Policy: opsdeploy.Policy{DefaultTimeout: policies.Execution.DefaultTimeout, HealthTimeout: policies.Execution.HealthTimeout, ReleaseRetain: policies.Releases.Retain, RequirePreviewDigest: true, RequireCleanArtifactManifest: true},
		Preflight: opsdeploy.Preflight{RemoteUser: "deploy", OS: "linux", Architecture: "amd64", DiskAvailableBytes: 1073741824, RequiredCommands: []opsdeploy.CommandEvidence{{Name: "mkdir", Available: true}, {Name: "tar", Available: true}}, Runner: opsdeploy.RunnerEvidence{Kind: "systemd", Identity: "demo.service", State: "running", Identified: true}, Health: opsdeploy.HealthEvidence{Type: "http", Executable: true, Healthy: true, StatusCode: 200}},
		Steps:     []opsdeploy.Step{{Order: 1, Kind: "upload-artifact", Scope: "remote", Access: opsdeploy.AccessWrite, Condition: "after-confirm", Program: "scp", Args: []string{"artifact", "remote"}}},
		Recovery:  opsdeploy.Recovery{Ready: true, Reason: "previous release available", Steps: []opsdeploy.Step{{Order: 1, Kind: "restore-current", Scope: "remote", Access: opsdeploy.AccessWrite, Condition: "on-compatible-failure", Program: "ln"}}},
	}
}

func mustDigest(t *testing.T, plan opsdeploy.Plan) string {
	t.Helper()
	digest, err := opsdeploy.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
func stepKinds(steps []opsdeploy.Step) []string {
	result := make([]string, len(steps))
	for i, step := range steps {
		result[i] = step.Kind
	}
	return result
}

func assertOrderedStepCommands(t *testing.T, steps, want []opsdeploy.Step) {
	t.Helper()
	position := 0
	for _, step := range steps {
		if position == len(want) || step.Kind != want[position].Kind {
			continue
		}
		if step.Program != want[position].Program || !reflect.DeepEqual(step.Args, want[position].Args) {
			t.Fatalf("step=%+v want=%+v", step, want[position])
		}
		position++
	}
	if position != len(want) {
		t.Fatalf("matched %d/%d commands; steps=%+v", position, len(want), steps)
	}
}
func hasWriteRequest(requests []opsexec.Request) bool {
	allowed := map[string]bool{"test": true, "readlink": true, "id": true, "uname": true, "df": true, "which": true, "systemctl": true, "sha256sum": true, "curl": true, "nc": true, "cat": true, "kill": true}
	for _, request := range requests {
		if !allowed[request.Program] {
			return true
		}
	}
	return false
}
