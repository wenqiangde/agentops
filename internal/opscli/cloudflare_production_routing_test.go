package opscli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestCloudflareProductionRoutingRequiresConfiguredCapabilityProfile(t *testing.T) {
	tests := []struct {
		file     string
		function string
	}{
		{file: "cloudflare.go", function: "opsCloudflareDeploy"},
		{file: "rollback.go", function: "opsCloudflareRollback"},
	}

	for _, test := range tests {
		t.Run(test.function, func(t *testing.T) {
			body := productionRouteFunctionBody(t, test.file, test.function)
			profile := strings.Index(body, "production.APIProfile")
			capability := strings.Index(body, "opscloudflarepayload.ParseWranglerConfig")
			apply := strings.Index(body, "opscloudflare.Apply")
			if profile < 0 || capability < 0 || apply < 0 || profile > apply || capability > apply {
				t.Fatalf("%s must validate production.APIProfile with ParseWranglerConfig before trusted apply", test.function)
			}
		})
	}
}

func TestCloudflareProductionRoutingRequiresExactProductionDigest(t *testing.T) {
	tests := []struct {
		file         string
		function     string
		confirmation string
		apply        string
	}{
		{file: "cloudflare.go", function: "opsCloudflareDeploy", confirmation: "opscloudflare.ConfirmProduction", apply: "opscloudflare.Apply"},
		{file: "rollback.go", function: "opsCloudflareRollback", confirmation: "opscloudflare.ConfirmProductionRollback", apply: "opscloudflare.ApplyRollback"},
	}

	for _, test := range tests {
		t.Run(test.function, func(t *testing.T) {
			body := productionRouteFunctionBody(t, test.file, test.function)
			confirmation := strings.Index(body, test.confirmation)
			apply := strings.Index(body, test.apply)
			if confirmation < 0 || apply < 0 || confirmation > apply {
				t.Fatalf("%s must verify the exact production digest with %s before trusted apply", test.function, test.confirmation)
			}
		})
	}
}

func TestCloudflareProductionRoutingRequiresTrustedProductionClient(t *testing.T) {
	tests := []struct {
		file     string
		function string
		apply    string
	}{
		{file: "cloudflare.go", function: "opsCloudflareDeploy", apply: "opscloudflare.Apply"},
		{file: "rollback.go", function: "opsCloudflareRollback", apply: "opscloudflare.ApplyRollback"},
	}

	for _, test := range tests {
		t.Run(test.function, func(t *testing.T) {
			function := productionRouteFunction(t, test.file, test.function)
			constructorFound := false
			applyFound := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := productionRouteCallName(call.Fun)
				if name == "opsCloudflareProductionClient" {
					constructorFound = true
				}
				if name == test.apply {
					applyFound = true
					if len(call.Args) < 2 || productionRouteNilIdentifier(call.Args[1]) {
						t.Fatalf("%s must pass a reviewed trusted production client to %s", test.function, test.apply)
					}
				}
				return true
			})
			if !constructorFound || !applyFound {
				t.Fatalf("%s must construct and route through the reviewed trusted production client", test.function)
			}
		})
	}
}

func productionRouteFunctionBody(t *testing.T, file, function string) string {
	t.Helper()
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	declaration := productionRouteFunctionFromContent(t, file, function, content)
	return string(content[declaration.Body.Pos()-1 : declaration.Body.End()-1])
}

func productionRouteFunction(t *testing.T, file, function string) *ast.FuncDecl {
	t.Helper()
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return productionRouteFunctionFromContent(t, file, function, content)
}

func productionRouteFunctionFromContent(t *testing.T, file, function string, content []byte) *ast.FuncDecl {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, content, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if ok && candidate.Name.Name == function && candidate.Body != nil {
			return candidate
		}
	}
	t.Fatalf("function %s was not found in %s", function, file)
	return nil
}

func productionRouteCallName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		prefix := productionRouteCallName(value.X)
		if prefix == "" {
			return value.Sel.Name
		}
		return prefix + "." + value.Sel.Name
	default:
		return ""
	}
}

func productionRouteNilIdentifier(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == "nil"
}
