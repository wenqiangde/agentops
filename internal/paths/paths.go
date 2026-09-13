package paths

import (
	"os"
	"path/filepath"
)

type Paths struct {
	OperationsRoot string
	OpsReportRoot  string
	OpsBackupRoot  string
	HomeDir        string
}

func Resolve() Paths {
	home, _ := os.UserHomeDir()
	if value := os.Getenv("AGENTOPS_HOME"); value != "" {
		home = value
	}
	root := filepath.Join(home, ".agentops", "operations")
	if value := os.Getenv("AGENTOPS_OPERATIONS"); value != "" {
		root = value
	}
	return Paths{
		OperationsRoot: root,
		OpsReportRoot:  filepath.Join(root, "reports"),
		OpsBackupRoot:  filepath.Join(root, "backups"),
		HomeDir:        home,
	}
}
