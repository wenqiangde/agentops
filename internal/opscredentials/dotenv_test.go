package opscredentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const dotenvSentinel = "SENTINEL_DO_NOT_LOG_9d78"

func assertSafeDotenvError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	switch err.Error() {
	case "CF_CREDENTIAL_FILE_SYNTAX", "CF_CREDENTIAL_FILE_TOO_LARGE",
		"CF_CREDENTIAL_FILE_OPEN", "CF_CREDENTIAL_FILE_STAT",
		"CF_CREDENTIAL_FILE_SECURITY", "CF_CREDENTIAL_FILE_READ", "CF_CREDENTIAL_FILE_CHANGED":
	default:
		t.Fatal("credential diagnostic is not a fixed safe code")
	}
}

func TestStrictDotenvSyntax(t *testing.T) {
	tests := []struct {
		name, input string
		invalid     bool
	}{
		{"plain", "TOKEN=" + dotenvSentinel + "\n", false},
		{"quotes CRLF", "TOKEN=\"" + dotenvSentinel + "\"\r\nOTHER='value'\r\n", false},
		{"export whitespace", "# comment\n export TOKEN = '" + dotenvSentinel + "'\n", false},
		{"empty value", "TOKEN=\n", false},
		{"duplicate", "TOKEN=one\nTOKEN=" + dotenvSentinel + "\n", true},
		{"duplicate export", "TOKEN=one\nexport TOKEN=two\n", true},
		{"invalid variable", "BAD-NAME=" + dotenvSentinel + "\n", true},
		{"numeric variable", "1TOKEN=value\n", true},
		{"interpolation", "TOKEN=${OTHER}\n", true},
		{"quoted interpolation", "TOKEN='${OTHER}'\n", true},
		{"command substitution", "TOKEN=$(echo " + dotenvSentinel + ")\n", true},
		{"backtick", "TOKEN=\x60echo " + dotenvSentinel + "\x60\n", true},
		{"multiline", "TOKEN=\"first\nsecond\"\n", true},
		{"unterminated", "TOKEN=\"" + dotenvSentinel + "\n", true},
		{"NUL", "TOKEN=" + dotenvSentinel + "\x00\n", true},
		{"control", "TOKEN=value\x01\n", true},
		{"bare CR", "TOKEN=value\rOTHER=value\n", true},
		{"yaml syntax", "TOKEN: " + dotenvSentinel + "\n", true},
		{"missing assignment", dotenvSentinel + "\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values, err := parseStrictDotenv([]byte(tt.input))
			assertSafeDotenvError(t, err)
			if (err != nil) != tt.invalid {
				t.Fatalf("invalid=%v error-present=%v", tt.invalid, err != nil)
			}
			if err != nil {
				if strings.Contains(err.Error(), dotenvSentinel) || strings.Contains(err.Error(), tt.input) {
					t.Fatal("parser error leaked input")
				}
				if values != nil {
					t.Fatal("failed parser returned partial secrets")
				}
			}
			if !tt.invalid && tt.name != "empty value" && values["TOKEN"] != dotenvSentinel {
				t.Fatal("literal token changed")
			}
		})
	}
}

func dotenvFixture(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadDotenvFileSecurity(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0640, 0644, 0400, 0700} {
		t.Run(mode.String(), func(t *testing.T) {
			path := dotenvFixture(t, "TOKEN="+dotenvSentinel+"\n", mode)
			values, err := readDotenv(path, os.Getuid(), nil)
			assertSafeDotenvError(t, err)
			if (err == nil) != (mode == 0600) {
				t.Fatalf("mode=%v error-present=%v", mode, err != nil)
			}
			if err != nil && (strings.Contains(err.Error(), dotenvSentinel) || strings.Contains(err.Error(), path)) {
				t.Fatal("file diagnostic leaked private data")
			}
			if err != nil && values != nil {
				t.Fatal("failed file read returned secrets")
			}
		})
	}
	t.Run("wrong owner identity", func(t *testing.T) {
		path := dotenvFixture(t, "TOKEN=value\n", 0600)
		if values, err := readDotenv(path, os.Getuid()+1, nil); err == nil || values != nil {
			t.Fatal("wrong expected owner accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		path := dotenvFixture(t, "TOKEN=value\n", 0600)
		link := filepath.Join(t.TempDir(), ".env")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readDotenv(link, os.Getuid(), nil); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := readDotenv(t.TempDir(), os.Getuid(), nil); err == nil {
			t.Fatal("directory accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".env")
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		// Must reject without blocking on opening a FIFO.
		if _, err := readDotenv(path, os.Getuid(), nil); err == nil {
			t.Fatal("FIFO accepted")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := readDotenv(filepath.Join(t.TempDir(), ".env"), os.Getuid(), nil); err == nil {
			t.Fatal("missing file accepted")
		}
	})
}

func TestDotenvSizeLimit(t *testing.T) {
	for _, size := range []int{64 * 1024, 64*1024 + 1} {
		path := dotenvFixture(t, "TOKEN="+strings.Repeat("a", size-len("TOKEN=\n"))+"\n", 0600)
		_, err := readDotenv(path, os.Getuid(), nil)
		assertSafeDotenvError(t, err)
		if (err != nil) != (size > 64*1024) {
			t.Fatalf("size=%d error-present=%v", size, err != nil)
		}
	}
}

func TestDotenvReplacementDuringRead(t *testing.T) {
	for _, action := range []string{"replace", "modify", "permissions"} {
		t.Run(action, func(t *testing.T) {
			path := dotenvFixture(t, "TOKEN="+dotenvSentinel+"\n", 0600)
			afterOpen := func() {
				switch action {
				case "replace":
					replacement := dotenvFixture(t, "TOKEN=other\n", 0600)
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "modify":
					if err := os.WriteFile(path, []byte("TOKEN=changed\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if values, err := readDotenv(path, os.Getuid(), afterOpen); err == nil || values != nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestDotenvDoesNotExportSecrets(t *testing.T) {
	t.Setenv("AGENTOPS_DOTENV_PRIVATE_SENTINEL", "process")
	path := dotenvFixture(t, "AGENTOPS_DOTENV_PRIVATE_SENTINEL=file\n", 0600)
	values, err := readDotenv(path, os.Getuid(), nil)
	if err != nil || values["AGENTOPS_DOTENV_PRIVATE_SENTINEL"] != "file" {
		t.Fatal("owned map read failed")
	}
	if os.Getenv("AGENTOPS_DOTENV_PRIVATE_SENTINEL") != "process" {
		t.Fatal("file loader mutated process environment")
	}
}
