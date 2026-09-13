package opsartifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestManifestBuildAndValidation(t *testing.T) {
	root := t.TempDir()
	writeBuildScript(t, root, true)
	if _, err := os.Stat(filepath.Join(root, "dist")); !os.IsNotExist(err) {
		t.Fatalf("clean build unexpectedly started with dist: %v", err)
	}
	service := artifactService()
	got, err := Build(context.Background(), opsexec.NewLocalExecutor(), root, service, Target{Platform: "linux", Architecture: "amd64"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Service != "demo-api" || got.Manifest.Version != "1.2.3" || got.Manifest.Commit != "0123456789abcdef" {
		t.Fatalf("manifest = %+v", got.Manifest)
	}
	if got.Size == 0 || got.ExpandedSize != int64(len("artifact")) || got.SHA256 != got.Manifest.SHA256 || !filepath.IsAbs(got.ArchivePath) {
		t.Fatalf("verified artifact = %+v", got)
	}
}

func TestValidateRejectsUnsafeArchiveEntries(t *testing.T) {
	for _, entry := range []tar.Header{
		{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},
		{Name: "/absolute", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},
		{Name: "bad\nname", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},
		{Name: ".agentsetup-artifact.tar.gz", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},
		{Name: "dir/link", Linkname: "../../escape", Typeflag: tar.TypeSymlink},
		{Name: "hard", Linkname: "../escape", Typeflag: tar.TypeLink},
	} {
		t.Run(entry.Name, func(t *testing.T) {
			root := t.TempDir()
			writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
			writeTarFixture(t, filepath.Join(root, "dist", "demo-api.tar.gz"), []tar.Header{entry}, [][]byte{[]byte("x")})
			rewriteFixtureDigest(t, root)
			if _, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestValidateAcceptsSafeDirectorySymlinkAndHardlinkEntries(t *testing.T) {
	root := t.TempDir()
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	headers := []tar.Header{
		{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "dir/app", Mode: 0o755, Size: 8, Typeflag: tar.TypeReg},
		{Name: "dir/current", Linkname: "app", Typeflag: tar.TypeSymlink},
		{Name: "app-copy", Linkname: "dir/app", Typeflag: tar.TypeLink},
	}
	writeTarFixture(t, filepath.Join(root, "dist", "demo-api.tar.gz"), headers, [][]byte{nil, []byte("artifact"), nil, nil})
	rewriteFixtureDigest(t, root)
	verified, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if verified.ExpandedSize != 8 {
		t.Fatalf("expanded size=%d want=8", verified.ExpandedSize)
	}
}

func TestManifestRejectsInvalidContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "service mismatch", mutate: func(m *Manifest) { m.Service = "other" }},
		{name: "target platform mismatch", mutate: func(m *Manifest) { m.Platform = "darwin" }},
		{name: "target architecture mismatch", mutate: func(m *Manifest) { m.Architecture = "arm64" }},
		{name: "empty version", mutate: func(m *Manifest) { m.Version = "" }},
		{name: "version whitespace", mutate: func(m *Manifest) { m.Version = "release 1" }},
		{name: "version path", mutate: func(m *Manifest) { m.Version = "release/1" }},
		{name: "version too long", mutate: func(m *Manifest) { m.Version = strings.Repeat("a", 129) }},
		{name: "empty commit", mutate: func(m *Manifest) { m.Commit = "" }},
		{name: "version control character", mutate: func(m *Manifest) { m.Version = "1.2.3\nforged" }},
		{name: "commit control character", mutate: func(m *Manifest) { m.Commit = "abc\tforged" }},
		{name: "zero built at", mutate: func(m *Manifest) { m.BuiltAt = time.Time{} }},
		{name: "uppercase digest", mutate: func(m *Manifest) { m.SHA256 = strings.ToUpper(m.SHA256) }},
		{name: "digest mismatch", mutate: func(m *Manifest) { m.SHA256 = strings.Repeat("0", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
			manifestPath := filepath.Join(root, "dist", "demo-api.manifest.json")
			manifest := readFixtureManifest(t, manifestPath)
			tt.mutate(&manifest)
			writeManifest(t, manifestPath, manifest, "")
			_, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"})
			if err == nil {
				t.Fatal("Validate succeeded, want error")
			}
		})
	}
}

func TestManifestRejectsEveryDuplicateField(t *testing.T) {
	root := t.TempDir()
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	path := filepath.Join(root, "dist", "demo-api.manifest.json")
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicates := map[string]string{
		"service": `"demo-api"`, "version": `"1.2.3"`, "commit": `"0123456789abcdef"`,
		"built_at": `"2026-09-12T01:02:03Z"`, "platform": `"linux"`,
		"architecture": `"amd64"`, "sha256": `"c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c"`,
	}
	for key, value := range duplicates {
		t.Run(key, func(t *testing.T) {
			data := append([]byte(nil), bytes.TrimSuffix(base, []byte("}"))...)
			data = append(data, []byte(`,"`+key+`":`+value+`}`)...)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}); err == nil {
				t.Fatal("duplicate manifest field was accepted")
			}
			if err := os.WriteFile(path, base, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManifestRejectsOversizedInputAndCancelledValidation(t *testing.T) {
	root := t.TempDir()
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	path := filepath.Join(root, "dist", "demo-api.manifest.json")
	if err := os.WriteFile(path, append([]byte(`{"service":"demo-api","padding":"`), bytes.Repeat([]byte("x"), manifestMaxBytes)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("oversized manifest was accepted")
	}
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ValidateContext(ctx, root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ValidateContext error = %v, want context cancellation", err)
	}
}

func TestVerifiedOpenRejectsChangedIdentityAndNonRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if file, err := openRegularVerified(path, oldInfo); err == nil {
		file.Close()
		t.Fatal("changed file identity was accepted")
	}
	if file, err := openRegularVerified(root, nil); err == nil {
		file.Close()
		t.Fatal("directory was accepted as regular file")
	}
}

func TestBuildRejectsUnchangedStaleOutputs(t *testing.T) {
	root := t.TempDir()
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	writeBuildScript(t, root, false)
	_, err := Build(context.Background(), opsexec.NewLocalExecutor(), root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}, 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("Build error = %v, want stale output rejection", err)
	}
}

func TestBuildRejectsWhenOnlyOneDeclaredOutputChanges(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{
			name:   "only manifest updated",
			script: "#!/bin/sh\nset -eu\nprintf '%s' '{\"service\":\"demo-api\",\"version\":\"1.2.4\",\"commit\":\"fedcba9876543210\",\"built_at\":\"2026-09-12T02:03:04Z\",\"platform\":\"linux\",\"architecture\":\"amd64\",\"sha256\":\"c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c\"}' > dist/demo-api.manifest.json\n",
		},
		{
			name:   "only artifact updated",
			script: "#!/bin/sh\nset -eu\nprintf temporary > dist/demo-api.tar.gz\nprintf artifact > dist/demo-api.tar.gz\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
			script := tt.script
			manifest := readFixtureManifest(t, filepath.Join(root, "dist", "demo-api.manifest.json"))
			script = strings.ReplaceAll(script, "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c", manifest.SHA256)
			if tt.name == "only artifact updated" {
				script = "#!/bin/sh\nset -eu\ncp fixture.tar.gz dist/demo-api.tar.gz\n"
			}
			if err := os.WriteFile(filepath.Join(root, "scripts", "build.sh"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := Build(context.Background(), opsexec.NewLocalExecutor(), root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}, 30*time.Second)
			if err == nil || !strings.Contains(err.Error(), "stale") {
				t.Fatalf("Build error = %v, want stale output rejection", err)
			}
		})
	}
}

func TestVerifiedRootRejectsReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(parent, "old-project")
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if file, err := openRootVerified(root, info); err == nil {
		file.Close()
		t.Fatal("replacement project root was accepted")
	}
}

func TestManifestRejectsUnknownFieldsMissingFilesAndSamePath(t *testing.T) {
	root := t.TempDir()
	writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
	manifestPath := filepath.Join(root, "dist", "demo-api.manifest.json")
	manifest := readFixtureManifest(t, manifestPath)
	writeManifest(t, manifestPath, manifest, `,"secret":"must-reject"`)
	if _, err := Validate(root, artifactService(), Target{Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}

	service := artifactService()
	service.Build.Manifest = service.Build.Artifact
	if _, err := Validate(root, service, Target{Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("same manifest and artifact path was accepted")
	}

	service = artifactService()
	service.Build.Manifest = "dist/missing.json"
	if _, err := Validate(root, service, Target{Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("missing manifest was accepted")
	}
	service = artifactService()
	service.Build.Artifact = "dist/missing.tar.gz"
	if _, err := Validate(root, service, Target{Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("missing artifact was accepted")
	}
}

func TestManifestRejectsPathEscapeAndSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	outsideArtifact := filepath.Join(outside, "artifact.tar.gz")
	if err := os.WriteFile(outsideArtifact, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		setup func(string, *opsconfig.Service)
	}{
		{name: "traversal", setup: func(_ string, s *opsconfig.Service) { s.Build.Artifact = "../artifact.tar.gz" }},
		{name: "absolute", setup: func(_ string, s *opsconfig.Service) { s.Build.Artifact = outsideArtifact }},
		{name: "symlink", setup: func(root string, _ *opsconfig.Service) {
			if err := os.Remove(filepath.Join(root, "dist", "demo-api.tar.gz")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideArtifact, filepath.Join(root, "dist", "demo-api.tar.gz")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "manifest symlink", setup: func(root string, _ *opsconfig.Service) {
			outsideManifest := filepath.Join(outside, "manifest.json")
			data, err := os.ReadFile(filepath.Join(root, "dist", "demo-api.manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(outsideManifest, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "dist", "demo-api.manifest.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsideManifest, filepath.Join(root, "dist", "demo-api.manifest.json")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeBuildFixture(t, root, "demo-api", "linux", "amd64", false)
			service := artifactService()
			tt.setup(root, &service)
			if _, err := Validate(root, service, Target{Platform: "linux", Architecture: "amd64"}); err == nil {
				t.Fatal("unsafe path was accepted")
			}
		})
	}
}

func TestBuildRejectsProjectRootWithControlCharacters(t *testing.T) {
	_, err := Build(context.Background(), opsexec.NewLocalExecutor(), "/tmp/project\nforged", artifactService(), Target{Platform: "linux", Architecture: "amd64"}, time.Second)
	if err == nil {
		t.Fatal("project root with control characters was accepted")
	}
}

func TestBuildRejectsUnsafeCommandAndDoesNotExposePayload(t *testing.T) {
	root := t.TempDir()
	service := artifactService()
	for _, command := range []string{"/tmp/build.sh", "../build.sh", "scripts/../build.sh", "scripts/build\n.sh"} {
		service.Build.Command = command
		if _, err := Build(context.Background(), opsexec.NewLocalExecutor(), root, service, Target{Platform: "linux", Architecture: "amd64"}, time.Second); err == nil {
			t.Fatalf("unsafe command %q was accepted", command)
		}
	}

	service = artifactService()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "build.sh"), []byte("#!/bin/sh\necho token=secret\necho password=secret >&2\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), opsexec.NewLocalExecutor(), root, service, Target{Platform: "linux", Architecture: "amd64"}, time.Second)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "password") {
		t.Fatalf("unsafe build error: %v", err)
	}
}

func artifactService() opsconfig.Service {
	return opsconfig.Service{ID: "demo-api", Build: opsconfig.Build{Adapter: "command", Command: "scripts/build.sh", Artifact: "dist/demo-api.tar.gz", Manifest: "dist/demo-api.manifest.json"}}
}

func writeBuildFixture(t *testing.T, root, service, platform, architecture string, fail bool) {
	t.Helper()
	writeBuildScript(t, root, !fail)
	if fail {
		return
	}
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "dist", "demo-api.tar.gz")
	writeTarFixture(t, archive, []tar.Header{{Name: "app", Mode: 0o755, Size: int64(len("artifact")), Typeflag: tar.TypeReg}}, [][]byte{[]byte("artifact")})
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	manifest := Manifest{Service: service, Version: "1.2.3", Commit: "0123456789abcdef", BuiltAt: time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC), Platform: platform, Architecture: architecture, SHA256: hex.EncodeToString(digest[:])}
	writeManifest(t, filepath.Join(root, "dist", "demo-api.manifest.json"), manifest, "")
}

func writeBuildScript(t *testing.T, root string, produce bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nset -eu\n"
	if produce {
		fixture := filepath.Join(root, "fixture.tar.gz")
		writeTarFixture(t, fixture, []tar.Header{{Name: "app", Mode: 0o755, Size: int64(len("artifact")), Typeflag: tar.TypeReg}}, [][]byte{[]byte("artifact")})
		data, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		script += fmt.Sprintf("mkdir -p dist\ncp fixture.tar.gz dist/demo-api.tar.gz\nprintf '%%s' '{\"service\":\"demo-api\",\"version\":\"1.2.3\",\"commit\":\"0123456789abcdef\",\"built_at\":\"2026-09-12T01:02:03Z\",\"platform\":\"linux\",\"architecture\":\"amd64\",\"sha256\":\"%s\"}' > dist/demo-api.manifest.json\n", hex.EncodeToString(digest[:]))
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "build.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeTarFixture(t *testing.T, filename string, headers []tar.Header, bodies [][]byte) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for index := range headers {
		header := headers[index]
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 && index < len(bodies) {
			if _, err := tw.Write(bodies[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func rewriteFixtureDigest(t *testing.T, root string) {
	t.Helper()
	archive, err := os.ReadFile(filepath.Join(root, "dist", "demo-api.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "dist", "demo-api.manifest.json")
	manifest := readFixtureManifest(t, manifestPath)
	digest := sha256.Sum256(archive)
	manifest.SHA256 = hex.EncodeToString(digest[:])
	writeManifest(t, manifestPath, manifest, "")
}

func writeManifest(t *testing.T, path string, manifest Manifest, extra string) {
	t.Helper()
	data := fmt.Sprintf(`{"service":%q,"version":%q,"commit":%q,"built_at":%q,"platform":%q,"architecture":%q,"sha256":%q%s}`,
		manifest.Service, manifest.Version, manifest.Commit, manifest.BuiltAt.Format(time.RFC3339), manifest.Platform, manifest.Architecture, manifest.SHA256, extra)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFixtureManifest(t *testing.T, path string) Manifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}
