package opscli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/paths"
)

func TestCloudflareCredentialsCommandRemoved(t *testing.T) {
	var output, errors bytes.Buffer
	code := executeAgentOpsCommand(paths.Paths{}, []string{"credentials", "doctor", "relay"}, &output, &errors)
	if code == 0 || !strings.Contains(errors.String(), "unknown command") {
		t.Fatalf("removed command accepted: code=%d error=%s", code, errors.String())
	}
}
