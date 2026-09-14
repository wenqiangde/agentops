package opscloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	hash := sha256.New()
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
			fmt.Fprintf(hash, "L\x00%s\x00%s\x00", filepath.ToSlash(relative), filepath.ToSlash(targetRelative))
		case entry.IsDir():
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil {
				return errors.New("Cloudflare source snapshot directory could not be created")
			}
			fmt.Fprintf(hash, "D\x00%s\x00%o\x00", filepath.ToSlash(relative), info.Mode().Perm())
		case info.Mode().IsRegular():
			content, err := os.ReadFile(path)
			if err != nil {
				return errors.New("Cloudflare source snapshot file could not be read")
			}
			if err := os.WriteFile(target, content, info.Mode().Perm()); err != nil {
				return errors.New("Cloudflare source snapshot file could not be created")
			}
			fmt.Fprintf(hash, "F\x00%s\x00%o\x00%d\x00", filepath.ToSlash(relative), info.Mode().Perm(), len(content))
			_, _ = hash.Write(content)
			_, _ = hash.Write([]byte{0})
		default:
			return errors.New("Cloudflare source snapshot contains an unsupported file")
		}
		return nil
	})
	if err != nil {
		cleanup()
		return SourceSnapshot{}, err
	}
	return SourceSnapshot{Path: targetRoot, SHA256: hex.EncodeToString(hash.Sum(nil)), cleanup: cleanup}, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
