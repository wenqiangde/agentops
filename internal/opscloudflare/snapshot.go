package opscloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type SourceSnapshot struct {
	Root    string
	Path    string
	SHA256  string
	cleanup func()
}

func (s SourceSnapshot) Cleanup() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

func CreateSourceSnapshot(source string) (SourceSnapshot, error) {
	return CreateDeploymentSnapshot(source, source, []string{"."})
}

func CreateDeploymentSnapshot(repositoryRoot, source string, scopes []string) (SourceSnapshot, error) {
	resolvedRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return SourceSnapshot{}, errors.New("Cloudflare repository root is unavailable")
	}
	rootInfo, err := os.Stat(resolvedRoot)
	if err != nil || !rootInfo.IsDir() {
		return SourceSnapshot{}, errors.New("Cloudflare repository root is unavailable")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
	}
	if !pathWithin(resolvedRoot, resolvedSource) {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
	}
	info, err := os.Stat(resolvedSource)
	if err != nil || !info.IsDir() {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
	}
	sourceRelative, err := filepath.Rel(resolvedRoot, resolvedSource)
	if err != nil {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
	}
	cleanScopes, err := validateSnapshotScopes(scopes, sourceRelative)
	if err != nil {
		return SourceSnapshot{}, err
	}
	container, err := os.MkdirTemp("", "agentops-cloudflare-")
	if err != nil {
		return SourceSnapshot{}, errors.New("Cloudflare source snapshot could not be created")
	}
	cleanup := func() { _ = os.RemoveAll(container) }
	targetRoot := filepath.Join(container, "source")
	if err := os.Mkdir(targetRoot, 0o700); err != nil {
		cleanup()
		return SourceSnapshot{}, errors.New("Cloudflare source snapshot could not be created")
	}
	rootFD, err := unix.Open(resolvedRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		cleanup()
		return SourceSnapshot{}, errors.New("Cloudflare repository root is unavailable")
	}
	defer unix.Close(rootFD)
	for _, scope := range cleanScopes {
		scopeFD, err := openSnapshotDirectory(rootFD, scope)
		if err != nil {
			cleanup()
			return SourceSnapshot{}, err
		}
		if err := copySnapshotDirectory(scopeFD, scope, targetRoot, cleanScopes); err != nil {
			cleanup()
			return SourceSnapshot{}, err
		}
	}
	digest, err := sourceSnapshotDigest(targetRoot)
	if err != nil {
		cleanup()
		return SourceSnapshot{}, err
	}
	return SourceSnapshot{Root: targetRoot, Path: filepath.Join(targetRoot, sourceRelative), SHA256: digest, cleanup: cleanup}, nil
}

func validateSnapshotScopes(scopes []string, sourceRelative string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errors.New("Cloudflare deployment scopes are required")
	}
	cleanScopes := make([]string, 0, len(scopes))
	sourceIncluded := false
	for _, scope := range scopes {
		clean := filepath.Clean(scope)
		if scope == "" || filepath.IsAbs(scope) || clean != scope || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, errors.New("Cloudflare deployment scope is invalid")
		}
		if pathWithinScope(sourceRelative, clean) {
			sourceIncluded = true
		}
		for _, existing := range cleanScopes {
			if pathWithinScope(clean, existing) || pathWithinScope(existing, clean) {
				return nil, errors.New("Cloudflare deployment scopes must be unique and non-overlapping")
			}
		}
		cleanScopes = append(cleanScopes, clean)
	}
	if !sourceIncluded {
		return nil, errors.New("Cloudflare source path is outside deployment scopes")
	}
	return cleanScopes, nil
}

func openSnapshotDirectory(rootFD int, relative string) (int, error) {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, errors.New("Cloudflare source snapshot could not be read")
	}
	if relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(current)
		if openErr != nil {
			return -1, errors.New("Cloudflare deployment scope is unavailable")
		}
		current = next
	}
	return current, nil
}

func copySnapshotDirectory(directoryFD int, relative, targetRoot string, scopes []string) error {
	directory := os.NewFile(uintptr(directoryFD), relative)
	if directory == nil {
		unix.Close(directoryFD)
		return errors.New("Cloudflare source snapshot could not be read")
	}
	defer directory.Close()
	targetDirectory := targetRoot
	if relative != "." {
		targetDirectory = filepath.Join(targetRoot, relative)
		if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
			return errors.New("Cloudflare source snapshot directory could not be created")
		}
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return errors.New("Cloudflare source snapshot could not be read")
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		entryRelative := entry.Name()
		if relative != "." {
			entryRelative = filepath.Join(relative, entry.Name())
		}
		var before unix.Stat_t
		if err := unix.Fstatat(directoryFD, entry.Name(), &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return errors.New("Cloudflare source snapshot entry is unavailable")
		}
		target := filepath.Join(targetRoot, entryRelative)
		switch before.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			childFD, err := unix.Openat(directoryFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil || !sameSnapshotIdentity(childFD, before) {
				if childFD >= 0 {
					unix.Close(childFD)
				}
				return errors.New("Cloudflare source snapshot directory changed during read")
			}
			if err := copySnapshotDirectory(childFD, entryRelative, targetRoot, scopes); err != nil {
				return err
			}
		case unix.S_IFREG:
			content, mode, err := readSnapshotFile(directoryFD, entry.Name(), before)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, content, mode); err != nil {
				return errors.New("Cloudflare source snapshot file could not be created")
			}
		case unix.S_IFLNK:
			linkTarget, err := readSnapshotLink(directoryFD, entry.Name())
			if err != nil || filepath.IsAbs(linkTarget) {
				return errors.New("Cloudflare source snapshot contains an unsafe symlink")
			}
			targetRelative := filepath.Clean(filepath.Join(filepath.Dir(entryRelative), linkTarget))
			if !pathInScopes(targetRelative, scopes) {
				return errors.New("Cloudflare source snapshot symlink is invalid")
			}
			snapshotTarget := filepath.Join(targetRoot, targetRelative)
			rewritten, err := filepath.Rel(filepath.Dir(target), snapshotTarget)
			if err != nil || os.Symlink(rewritten, target) != nil {
				return errors.New("Cloudflare source snapshot symlink could not be created")
			}
		default:
			return errors.New("Cloudflare source snapshot contains an unsupported file")
		}
	}
	return nil
}

func readSnapshotFile(directoryFD int, name string, expected unix.Stat_t) ([]byte, os.FileMode, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil || !sameSnapshotIdentity(fd, expected) {
		if fd >= 0 {
			unix.Close(fd)
		}
		return nil, 0, errors.New("Cloudflare source snapshot file changed during read")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, errors.New("Cloudflare source snapshot file could not be read")
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !sameStat(expected, after) {
		return nil, 0, errors.New("Cloudflare source snapshot file changed during read")
	}
	return content, os.FileMode(expected.Mode & 0o777), nil
}

func readSnapshotLink(directoryFD int, name string) (string, error) {
	buffer := make([]byte, 4096)
	count, err := unix.Readlinkat(directoryFD, name, buffer)
	if err != nil || count == len(buffer) {
		return "", errors.New("Cloudflare source snapshot symlink is unavailable")
	}
	return string(buffer[:count]), nil
}

func sameSnapshotIdentity(fd int, expected unix.Stat_t) bool {
	if fd < 0 {
		return false
	}
	var actual unix.Stat_t
	return unix.Fstat(fd, &actual) == nil && actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode&unix.S_IFMT == expected.Mode&unix.S_IFMT
}

func sameStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Size == right.Size && left.Mtim == right.Mtim
}

func pathInScopes(relative string, scopes []string) bool {
	for _, scope := range scopes {
		if pathWithinScope(relative, scope) {
			return true
		}
	}
	return false
}

func pathWithinScope(relative, scope string) bool {
	if scope == "." {
		return relative == "." || relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return relative == scope || strings.HasPrefix(relative, scope+string(filepath.Separator))
}

func SealSourceSnapshot(root, expectedSHA256 string) error {
	digest, err := sourceSnapshotDigest(root)
	if err != nil || digest != expectedSHA256 {
		return errors.New("Cloudflare source snapshot digest is stale")
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("Cloudflare source snapshot could not be sealed")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("Cloudflare source snapshot could not be sealed")
		}
		mode := info.Mode().Perm() &^ 0o222
		if entry.IsDir() {
			mode |= 0o500
		}
		if err := os.Chmod(path, mode); err != nil {
			return errors.New("Cloudflare source snapshot could not be sealed")
		}
		return nil
	})
}

func sourceSnapshotDigest(root string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("Cloudflare source snapshot root is unavailable")
	}
	hash := sha256.New()
	err = filepath.WalkDir(resolvedRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("Cloudflare source snapshot could not be verified")
		}
		relative, err := filepath.Rel(resolvedRoot, path)
		if err != nil || relative == "." {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("Cloudflare source snapshot entry is unavailable")
		}
		mode := info.Mode().Perm() &^ 0o222
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			target, err := filepath.EvalSymlinks(path)
			if err != nil || !pathWithin(resolvedRoot, target) {
				return errors.New("Cloudflare source snapshot contains an unsafe symlink")
			}
			targetRelative, _ := filepath.Rel(resolvedRoot, target)
			fmt.Fprintf(hash, "L\x00%s\x00%s\x00", filepath.ToSlash(relative), filepath.ToSlash(targetRelative))
		case entry.IsDir():
			fmt.Fprintf(hash, "D\x00%s\x00%o\x00", filepath.ToSlash(relative), mode)
		case info.Mode().IsRegular():
			content, err := readNoFollow(path, info)
			if err != nil {
				return err
			}
			fmt.Fprintf(hash, "F\x00%s\x00%o\x00%d\x00", filepath.ToSlash(relative), mode, len(content))
			_, _ = hash.Write(content)
			_, _ = hash.Write([]byte{0})
		default:
			return errors.New("Cloudflare source snapshot contains an unsupported file")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readNoFollow(path string, expected fs.FileInfo) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Cloudflare source snapshot file could not be read")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(expected, before) {
		return nil, errors.New("Cloudflare source snapshot file changed during read")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.New("Cloudflare source snapshot file could not be read")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("Cloudflare source snapshot file changed during read")
	}
	return content, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
