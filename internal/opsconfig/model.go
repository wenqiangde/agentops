package opsconfig

import "strings"

const (
	EnvironmentLocal      = "local"
	EnvironmentProduction = "production"

	EnvironmentKindLocal = "local"
	EnvironmentKindSSH   = "ssh"

	RunnerSystemd = "systemd"
	RunnerPHPFPM  = "php-fpm"
	RunnerPM2     = "pm2"
	RunnerProcess = "process"
	RunnerManual  = "manual"
)

var (
	EnvironmentKinds = []string{EnvironmentKindLocal, EnvironmentKindSSH}
	RunnerKinds      = []string{RunnerSystemd, RunnerPHPFPM, RunnerPM2, RunnerProcess, RunnerManual}
)

type Inventory struct {
	Services map[string]Service
	Hosts    map[string]Host
	Policies Policies
}

type Service struct {
	Version         int                       `yaml:"version"`
	ID              string                    `yaml:"id"`
	Language        string                    `yaml:"language"`
	Source          Source                    `yaml:"source"`
	Build           Build                     `yaml:"build"`
	Environments    map[string]Environment    `yaml:"environments"`
	Data            Data                      `yaml:"data,omitempty"`
	FutureResources map[string]FutureResource `yaml:"futureResources,omitempty"`
	SourceFile      string                    `yaml:"-"`
}

type Source struct {
	Path       string `yaml:"path"`
	Repository string `yaml:"repository"`
}

type Build struct {
	Adapter  string `yaml:"adapter"`
	Command  string `yaml:"command"`
	Artifact string `yaml:"artifact"`
	Manifest string `yaml:"manifest"`
}

func (service Service) BuildConfigured() bool {
	return strings.TrimSpace(service.Build.Adapter) != "" ||
		strings.TrimSpace(service.Build.Command) != "" ||
		strings.TrimSpace(service.Build.Artifact) != "" ||
		strings.TrimSpace(service.Build.Manifest) != ""
}

type Environment struct {
	Kind           string         `yaml:"kind"`
	Host           string         `yaml:"host,omitempty"`
	Root           string         `yaml:"root,omitempty"`
	Runner         string         `yaml:"runner"`
	Unit           string         `yaml:"unit,omitempty"`
	Service        string         `yaml:"service,omitempty"`
	App            string         `yaml:"app,omitempty"`
	ConfigOwner    string         `yaml:"configOwner,omitempty"`
	ConfigPath     string         `yaml:"configPath,omitempty"`
	User           string         `yaml:"user,omitempty"`
	Command        string         `yaml:"command,omitempty"`
	PIDFile        string         `yaml:"pidfile,omitempty"`
	ShutdownSignal string         `yaml:"shutdownSignal,omitempty"`
	Logs           string         `yaml:"logs,omitempty"`
	Config         ConfigContract `yaml:"config,omitempty"`
	Health         Health         `yaml:"health,omitempty"`
}

type ConfigContract struct {
	Files        []string `yaml:"files,omitempty"`
	RequiredKeys []string `yaml:"requiredKeys,omitempty"`
	SecretKeys   []string `yaml:"secretKeys,omitempty"`
}

type Health struct {
	Type            string        `yaml:"type,omitempty"`
	URL             string        `yaml:"url,omitempty"`
	Address         string        `yaml:"address,omitempty"`
	Command         *CommandProbe `yaml:"command,omitempty"`
	SuccessStatuses []int         `yaml:"successStatuses,omitempty"`
}

type CommandProbe struct {
	Program string   `yaml:"program"`
	Args    []string `yaml:"args,omitempty"`
}

type Data struct {
	MySQL *MySQLData `yaml:"mysql,omitempty"`
}

type MySQLData struct {
	Resource         string `yaml:"resource"`
	MigrationCommand string `yaml:"migrationCommand"`
	BackupPolicy     string `yaml:"backupPolicy"`
}

type FutureResource struct {
	Status        string   `yaml:"status"`
	IntendedRoles []string `yaml:"intendedRoles,omitempty"`
}

type HostsFile struct {
	Version int             `yaml:"version"`
	Hosts   map[string]Host `yaml:"hosts"`
}

type Host struct {
	SSHAlias     string   `yaml:"sshAlias"`
	Platform     string   `yaml:"platform"`
	Architecture string   `yaml:"architecture"`
	Capabilities []string `yaml:"capabilities,omitempty"`
	AllowedRoots []string `yaml:"allowedRoots,omitempty"`
	Hostname     string   `yaml:"host,omitempty"`
	Port         int      `yaml:"port,omitempty"`
	User         string   `yaml:"user,omitempty"`
}

type Policies struct {
	Version    int                `yaml:"version"`
	Execution  ExecutionPolicies  `yaml:"execution"`
	Production ProductionPolicies `yaml:"production"`
	Releases   ReleasePolicies    `yaml:"releases"`
	Backups    BackupPolicies     `yaml:"backups"`
}

type ExecutionPolicies struct {
	DefaultTimeout   string `yaml:"defaultTimeout"`
	HealthTimeout    string `yaml:"healthTimeout"`
	BatchConcurrency int    `yaml:"batchConcurrency"`
}

type ProductionPolicies struct {
	RequirePreviewDigest         bool `yaml:"requirePreviewDigest"`
	RequireCleanArtifactManifest bool `yaml:"requireCleanArtifactManifest"`
}

type ReleasePolicies struct {
	Retain int `yaml:"retain"`
}

type BackupPolicies struct {
	ServerCopies      int  `yaml:"serverCopies"`
	LocalCopies       int  `yaml:"localCopies"`
	RequireEncryption bool `yaml:"requireEncryption"`
}

type Issue struct {
	File    string
	Field   string
	Message string
}
