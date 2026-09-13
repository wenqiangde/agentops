package opsdeploy

import (
	"strings"
	"testing"
)

func TestParseSHA256SumGNUFilenameEscapes(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, tt := range []struct {
		name   string
		output string
		path   string
	}{
		{name: "spaces", output: digest + "  /tmp/app file.env\n", path: "/tmp/app file.env"},
		{name: "backslash", output: `\` + digest + `  /tmp/app\\name.env` + "\n", path: `/tmp/app\name.env`},
		{name: "newline", output: `\` + digest + `  /tmp/app\nname.env` + "\n", path: "/tmp/app\nname.env"},
		{name: "carriage return", output: `\` + digest + `  /tmp/app\rname.env` + "\n", path: "/tmp/app\rname.env"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gotDigest, gotPath, ok := parseSHA256Sum(tt.output)
			if !ok || gotDigest != digest || gotPath != tt.path {
				t.Fatalf("digest=%q path=%q ok=%v", gotDigest, gotPath, ok)
			}
		})
	}
}
