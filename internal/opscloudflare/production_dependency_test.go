package opscloudflare_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCloudflareProductionActionsContainNoProcessOrProjectInputDependency(t *testing.T) {
	for _, target := range []struct {
		file     string
		function string
	}{
		{file: "apply.go", function: "Apply"},
		{file: "rollback.go", function: "ApplyRollback"},
	} {
		t.Run(target.function, func(t *testing.T) {
			path := filepath.Join(".", target.file)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, content, 0)
			if err != nil {
				t.Fatal(err)
			}
			var body string
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != target.function || function.Body == nil {
					continue
				}
				body = string(content[function.Body.Pos()-1 : function.Body.End()-1])
			}
			if body == "" {
				t.Fatalf("production function %s was not found", target.function)
			}
			for _, forbidden := range []string{"opsexec", "executor.Run", "node_modules/.bin/wrangler", "SourcePath", "WranglerConfig"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("production function %s contains forbidden dependency %s", target.function, strconv.Quote(forbidden))
				}
			}
		})
	}
}
