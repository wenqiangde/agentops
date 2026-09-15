package opscli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudflareProductionGateIsClosedAndHasNoRuntimeBypass(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	declarationFound := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(".", entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.ValueSpec:
				for index, name := range value.Names {
					if name.Name != "cloudflareProductionWritesEnabled" {
						continue
					}
					declarationFound = true
					literal, ok := value.Values[index].(*ast.Ident)
					if !ok || literal.Name != "false" {
						t.Fatalf("production gate must be initialized to false in %s", path)
					}
				}
			case *ast.AssignStmt:
				for _, expression := range value.Lhs {
					if identifier, ok := expression.(*ast.Ident); ok && identifier.Name == "cloudflareProductionWritesEnabled" {
						t.Fatalf("production source assigns Cloudflare gate at runtime in %s", path)
					}
				}
			}
			return true
		})
	}
	if !declarationFound {
		t.Fatal("Cloudflare production gate declaration was not found")
	}

	assertGateBeforeTrustedCall(t, "cloudflare.go", "opsCloudflareDeploy", "opscloudflare.Apply")
	assertGateBeforeTrustedCall(t, "rollback.go", "opsCloudflareRollback", "opscloudflare.ApplyRollback")
}

func assertGateBeforeTrustedCall(t *testing.T, file, function, trustedCall string) {
	t.Helper()
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, content, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, declaration := range parsed.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if ok && candidate.Name.Name == function && candidate.Body != nil {
			body = string(content[candidate.Body.Pos()-1 : candidate.Body.End()-1])
			break
		}
	}
	gate := strings.Index(body, "!cloudflareProductionWritesEnabled")
	call := strings.Index(body, trustedCall)
	if gate < 0 || call < 0 || gate > call {
		t.Fatalf("%s must reject the closed gate before %s", function, trustedCall)
	}
}
