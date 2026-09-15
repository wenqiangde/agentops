package opscloudflarepayload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestIsolationSpikeSourceMutationDoesNotChangeFrozenPayload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker.mjs")
	writeSpikeFile(t, path, "approved")
	payload, err := opscloudflarepayload.Capture(root, []string{"worker.mjs"})
	if err != nil {
		t.Fatal(err)
	}
	writeSpikeFile(t, path, "mutated")
	assertFrozenFile(t, payload, "worker.mjs", "approved")
}

func TestIsolationSpikeRetainedDescriptorDoesNotChangeFrozenPayload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker.mjs")
	writeSpikeFile(t, path, "approved")
	retained, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	payload, err := opscloudflarepayload.Capture(root, []string{"worker.mjs"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retained.WriteAt([]byte("mutated!"), 0); err != nil {
		t.Fatal(err)
	}
	assertFrozenFile(t, payload, "worker.mjs", "approved")
}

func TestIsolationSpikeBackgroundChildDoesNotChangeFrozenPayload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worker.mjs")
	gate := filepath.Join(root, "mutate-now")
	writeSpikeFile(t, path, "approved")
	child := exec.Command(os.Args[0], "-test.run=TestIsolationSpikeMutationHelper", "--", path, gate)
	child.Env = append(os.Environ(), "AGENTOPS_ISOLATION_SPIKE_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	payload, err := opscloudflarepayload.Capture(root, []string{"worker.mjs"})
	if err != nil {
		_ = child.Process.Kill()
		t.Fatal(err)
	}
	writeSpikeFile(t, gate, "go")
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	assertFrozenFile(t, payload, "worker.mjs", "approved")
}

func TestIsolationSpikeRejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "secret")
	writeSpikeFile(t, external, "secret")
	if _, err := opscloudflarepayload.Capture(root, []string{external}); err == nil {
		t.Fatal("outside path was accepted")
	}
}

func TestIsolationSpikeRejectsFinalAndIntermediateSymlinks(t *testing.T) {
	root := t.TempDir()
	writeSpikeFile(t, filepath.Join(root, "real", "worker.mjs"), "approved")
	if err := os.Symlink(filepath.Join("real", "worker.mjs"), filepath.Join(root, "worker-link.mjs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "directory-link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"worker-link.mjs", filepath.Join("directory-link", "worker.mjs")} {
		if _, err := opscloudflarepayload.Capture(root, []string{path}); err == nil {
			t.Fatalf("symlink path accepted: %s", path)
		}
	}
}

func TestIsolationSpikeRejectsDuplicateInput(t *testing.T) {
	root := t.TempDir()
	writeSpikeFile(t, filepath.Join(root, "worker.mjs"), "approved")
	if _, err := opscloudflarepayload.Capture(root, []string{"worker.mjs", "worker.mjs"}); err == nil {
		t.Fatal("duplicate payload input was accepted")
	}
}

func TestIsolationSpikeDigestRepresentsCapturedBytes(t *testing.T) {
	root := t.TempDir()
	writeSpikeFile(t, filepath.Join(root, "worker.mjs"), "approved")
	payload, err := opscloudflarepayload.Capture(root, []string{"worker.mjs"})
	if err != nil {
		t.Fatal(err)
	}
	content, _ := payload.File("worker.mjs")
	hash := sha256.New()
	hash.Write([]byte("worker.mjs\x008\x00"))
	hash.Write(content)
	hash.Write([]byte{0})
	if payload.SHA256() != hex.EncodeToString(hash.Sum(nil)) {
		t.Fatalf("digest does not represent captured bytes: %s", payload.SHA256())
	}
}

func TestIsolationSpikeTransportReceivesOwnedPayloadWithoutPaths(t *testing.T) {
	root := t.TempDir()
	writeSpikeFile(t, filepath.Join(root, "worker.mjs"), "approved")
	payload, err := opscloudflarepayload.Capture(root, []string{"worker.mjs"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingSpikeTransport{}
	if err := opscloudflarepayload.Deliver(context.Background(), payload, transport); err != nil {
		t.Fatal(err)
	}
	writeSpikeFile(t, filepath.Join(root, "worker.mjs"), "mutated")
	assertFrozenFile(t, transport.payload, "worker.mjs", "approved")
	if transport.payload.SHA256() != payload.SHA256() {
		t.Fatal("transport payload digest changed")
	}
}

type recordingSpikeTransport struct {
	payload opscloudflarepayload.Payload
}

func (r *recordingSpikeTransport) Send(_ context.Context, payload opscloudflarepayload.Payload) error {
	r.payload = payload
	return nil
}

func TestIsolationSpikeMutationHelper(t *testing.T) {
	if os.Getenv("AGENTOPS_ISOLATION_SPIKE_HELPER") != "1" {
		return
	}
	separator := -1
	for index, value := range os.Args {
		if value == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+3 {
		os.Exit(2)
	}
	path, gate := os.Args[separator+1], os.Args[separator+2]
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(3)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(path, []byte("mutated"), 0o600); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func assertFrozenFile(t *testing.T, payload opscloudflarepayload.Payload, name, expected string) {
	t.Helper()
	content, ok := payload.File(name)
	if !ok || string(content) != expected {
		t.Fatalf("frozen file=%q exists=%v", content, ok)
	}
	content[0] = 'x'
	again, _ := payload.File(name)
	if string(again) != expected {
		t.Fatalf("caller mutated frozen payload: %q", again)
	}
}

func writeSpikeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
