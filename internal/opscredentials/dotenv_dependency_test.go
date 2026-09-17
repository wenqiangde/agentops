package opscredentials

import (
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestPinnedDotenvParserContract(t *testing.T) {
	t.Setenv("AGENTOPS_DOTENV_SENTINEL", "process")
	values, err := godotenv.Parse(strings.NewReader("AGENTOPS_DOTENV_SENTINEL=\"file\"\r\nOTHER='quoted'\r\n"))
	if err != nil || values["AGENTOPS_DOTENV_SENTINEL"] != "file" || values["OTHER"] != "quoted" {
		t.Fatal("quoted CRLF parsing contract changed")
	}
	if os.Getenv("AGENTOPS_DOTENV_SENTINEL") != "process" {
		t.Fatal("parser mutated process environment")
	}
	// These permissive upstream behaviors require our strict pre-validation gate.
	values, err = godotenv.Parse(strings.NewReader("A=first\nA=second\nB=${A}\n"))
	if err != nil || values["A"] != "second" || values["B"] != "second" {
		t.Fatal("upstream duplicate/interpolation behavior changed")
	}
}
