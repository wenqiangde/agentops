package opsgit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	StateClean = "clean"
	StateDirty = "dirty"
)

type Request struct {
	RepositoryRoot string
	Scopes         []string
}

type Evidence struct {
	RepositoryRoot string
	BaseCommit     string
	State          string
	Entries        []Entry
	ContentSHA256  string
}

type Entry struct {
	Path           string
	OriginalPath   string
	IndexStatus    string
	WorktreeStatus string
	SHA256         string
}

func Inspect(ctx context.Context, request Request) (Evidence, error) {
	if ctx == nil {
		return Evidence{}, errors.New("Git inspection context is required")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	root, scopes, err := validateRequest(request)
	if err != nil {
		return Evidence{}, err
	}
	actualRoot, err := runGit(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		return Evidence{}, fmt.Errorf("resolve Git repository root: %w", err)
	}
	if same, err := sameDirectory(root, strings.TrimSpace(string(actualRoot))); err != nil {
		return Evidence{}, fmt.Errorf("compare Git repository root: %w", err)
	} else if !same {
		return Evidence{}, errors.New("configured repository root does not match Git repository root")
	}
	commitOutput, err := runGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return Evidence{}, fmt.Errorf("resolve Git base commit: %w", err)
	}
	baseCommit := strings.TrimSpace(string(commitOutput))

	statusArgs := []string{"status", "--porcelain=v1", "-z", "--untracked-files=all", "--"}
	statusArgs = append(statusArgs, scopes...)
	statusOutput, err := runGit(ctx, root, statusArgs...)
	if err != nil {
		return Evidence{}, fmt.Errorf("inspect Git deployment scope: %w", err)
	}
	entries, err := parsePorcelain(statusOutput)
	if err != nil {
		return Evidence{}, err
	}

	listArgs := []string{"ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"}
	listArgs = append(listArgs, scopes...)
	listOutput, err := runGit(ctx, root, listArgs...)
	if err != nil {
		return Evidence{}, fmt.Errorf("list Git deployment scope: %w", err)
	}
	paths := splitNUL(listOutput)
	sort.Strings(paths)
	deleted := make(map[string]bool)
	for _, entry := range entries {
		if entry.IndexStatus == "D" || entry.WorktreeStatus == "D" {
			deleted[entry.Path] = true
		}
	}
	digest, fileDigests, err := digestFiles(ctx, root, baseCommit, paths, deleted)
	if err != nil {
		return Evidence{}, err
	}
	statusAfter, err := runGit(ctx, root, statusArgs...)
	if err != nil {
		return Evidence{}, fmt.Errorf("recheck Git deployment scope: %w", err)
	}
	listAfter, err := runGit(ctx, root, listArgs...)
	if err != nil {
		return Evidence{}, fmt.Errorf("recheck Git deployment files: %w", err)
	}
	if !bytes.Equal(statusOutput, statusAfter) || !bytes.Equal(listOutput, listAfter) {
		return Evidence{}, errors.New("Git deployment scope changed during inspection")
	}
	for index := range entries {
		entries[index].SHA256 = fileDigests[entries[index].Path]
	}
	state := StateClean
	if len(entries) != 0 {
		state = StateDirty
	}
	return Evidence{
		RepositoryRoot: root,
		BaseCommit:     baseCommit,
		State:          state,
		Entries:        entries,
		ContentSHA256:  digest,
	}, nil
}

func sameDirectory(left, right string) (bool, error) {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false, err
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return false, err
	}
	return leftInfo.IsDir() && rightInfo.IsDir() && os.SameFile(leftInfo, rightInfo), nil
}

func validateRequest(request Request) (string, []string, error) {
	root := filepath.Clean(request.RepositoryRoot)
	if request.RepositoryRoot == "" || !filepath.IsAbs(request.RepositoryRoot) || root != request.RepositoryRoot || root == string(filepath.Separator) {
		return "", nil, errors.New("repository root must be a canonical absolute path")
	}
	if len(request.Scopes) == 0 {
		return "", nil, errors.New("at least one deployment scope is required")
	}
	scopes := append([]string(nil), request.Scopes...)
	for index, scope := range scopes {
		clean := filepath.Clean(scope)
		if scope == "" || !utf8.ValidString(scope) || strings.ContainsAny(scope, "\x00\r\n\t") || filepath.IsAbs(scope) || clean != scope || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", nil, errors.New("deployment scopes must be clean relative paths")
		}
		for previous := 0; previous < index; previous++ {
			if scope == scopes[previous] || strings.HasPrefix(scope, scopes[previous]+string(filepath.Separator)) || strings.HasPrefix(scopes[previous], scope+string(filepath.Separator)) {
				return "", nil, errors.New("deployment scopes must be unique and non-overlapping")
			}
		}
	}
	return root, scopes, nil
}

func runGit(ctx context.Context, root string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	output, err := command.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return output, nil
}

func parsePorcelain(output []byte) ([]Entry, error) {
	fields := splitNUL(output)
	entries := make([]Entry, 0, len(fields))
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if len(field) < 4 || field[2] != ' ' {
			return nil, errors.New("invalid Git porcelain status output")
		}
		entry := Entry{
			IndexStatus:    field[0:1],
			WorktreeStatus: field[1:2],
			Path:           field[3:],
		}
		if err := validateGitPath(entry.Path); err != nil {
			return nil, err
		}
		if entry.IndexStatus == "R" || entry.IndexStatus == "C" {
			index++
			if index >= len(fields) {
				return nil, errors.New("invalid Git porcelain rename output")
			}
			entry.OriginalPath = fields[index]
			if err := validateGitPath(entry.OriginalPath); err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func validateGitPath(path string) error {
	if path == "" || !utf8.ValidString(path) || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("Git path contains unsupported characters")
	}
	return nil
}

func splitNUL(output []byte) []string {
	parts := bytes.Split(output, []byte{0})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			result = append(result, string(part))
		}
	}
	return result
}

func digestFiles(ctx context.Context, root, baseCommit string, paths []string, deleted map[string]bool) (string, map[string]string, error) {
	overall := sha256.New()
	overall.Write([]byte("base\x00" + baseCommit + "\x00"))
	fileDigests := make(map[string]string, len(paths))
	for _, relative := range paths {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if err := validateGitPath(relative); err != nil {
			return "", nil, err
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) && deleted[relative] {
				overall.Write([]byte("deleted\x00" + relative + "\x00"))
				continue
			}
			return "", nil, fmt.Errorf("inspect scoped file %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", nil, fmt.Errorf("scoped file %q is a symbolic link", relative)
		}
		if !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("scoped file %q is not regular", relative)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", nil, fmt.Errorf("read scoped file %q: %w", relative, err)
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
			return "", nil, fmt.Errorf("scoped file %q changed during inspection", relative)
		}
		fileDigest := sha256.Sum256(content)
		encoded := hex.EncodeToString(fileDigest[:])
		fileDigests[relative] = encoded
		overall.Write([]byte("file\x00" + relative + "\x00" + encoded + "\x00"))
	}
	return hex.EncodeToString(overall.Sum(nil)), fileDigests, nil
}
