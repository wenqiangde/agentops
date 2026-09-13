package main

import (
	"os"

	"github.com/wenqiangde/agentops/internal/opscli"
)

func main() {
	os.Exit(opscli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
