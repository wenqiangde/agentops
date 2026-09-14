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
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
	}
	info, err := os.Stat(resolvedSource)
	if err != nil || !info.IsDir() {
		return SourceSnapshot{}, errors.New("Cloudflare source path is unavailable")
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
	err = filepath.WalkDir(resolvedSource, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("Cloudflare source snapshot could not be read")
		}
		relative, err := filepath.Rel(resolvedSource, path)
		if err != nil {
			return errors.New("Cloudflare source snapshot path is invalid")
		}
		if relative == ".git" || strings.HasPrefix(relative, ".git"+string(filepath.Separator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if relative == "." {
			return nil
		}
		target := filepath.Join(targetRoot, relative)
		info, err := entry.Info()
		if err != nil {
			return errors.New("Cloudflare source snapshot entry is unavailable")
		}
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			resolvedTarget, err := filepath.EvalSymlinks(path)
			if err != nil || !pathWithin(resolvedSource, resolvedTarget) {
				return errors.New("Cloudflare source snapshot contains an unsafe symlink")
			}
			targetRelative, err := filepath.Rel(resolvedSource, resolvedTarget)
			if err != nil {
				return errors.New("Cloudflare source snapshot symlink is invalid")
			}
			snapshotTarget := filepath.Join(targetRoot, targetRelative)
			linkTarget, err := filepath.Rel(filepath.Dir(target), snapshotTarget)
			if err != nil || os.Symlink(linkTarget, target) != nil {
				return errors.New("Cloudflare source snapshot symlink could not be created")
			}
		case entry.IsDir():
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
				return errors.New("Cloudflare source snapshot directory could not be created")
			}
		case info.Mode().IsRegular():
			content, err := readNoFollow(path, info)
			if err != nil {
				return errors.New("Cloudflare source snapshot file could not be read")
			}
			if err := os.WriteFile(target, content, info.Mode().Perm()); err != nil {
				return errors.New("Cloudflare source snapshot file could not be created")
			}
		default:
			return errors.New("Cloudflare source snapshot contains an unsupported file")
		}
		return nil
	})
	if err != nil {
		cleanup()
		return SourceSnapshot{}, err
	}
	digest, err := sourceSnapshotDigest(targetRoot)
	if err != nil {
		cleanup()
		return SourceSnapshot{}, err
	}
	return SourceSnapshot{Path: targetRoot, SHA256: digest, cleanup: cleanup}, nil
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
