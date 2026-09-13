package opscli

import "fmt"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
	channel = "source"
)

func versionText() string {
	return fmt.Sprintf(`AgentOps Version

Version: %s
Commit: %s
Build date: %s
Channel: %s
`, version, commit, date, channel)
}
