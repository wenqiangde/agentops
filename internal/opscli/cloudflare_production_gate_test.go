package opscli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestCloudflareProductionRoutingHasNoRuntimeBooleanBypass(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifier.Name == "cloudflareProductionWritesEnabled" {
				t.Fatalf("legacy runtime production boolean remains in %s", entry.Name())
			}
			return true
		})
	}
}
