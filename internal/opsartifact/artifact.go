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
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"golang.org/x/sys/unix"
)

var lowercaseSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var safeVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)

const manifestMaxBytes = 64 * 1024

type Manifest struct {
	Service      string    `json:"service"`
	Version      string    `json:"version"`
	Commit       string    `json:"commit"`
	BuiltAt      time.Time `json:"built_at"`
	Platform     string    `json:"platform"`
	Architecture string    `json:"architecture"`
	SHA256       string    `json:"sha256"`
}

type Target struct {
	Platform     string
	Architecture string
}

type Verified struct {
	Manifest     Manifest
	ArchivePath  string
	Size         int64
	ExpandedSize int64
	SHA256       string
}

func Build(ctx context.Context, executor opsexec.Executor, projectRoot string, service opsconfig.Service, target Target, timeout time.Duration) (Verified, error) {
	if ctx == nil {
		return Verified{}, errors.New("build context is required")
	}
	if executor == nil {
		return Verified{}, errors.New("build executor is required")
	}
	if timeout <= 0 {
		return Verified{}, errors.New("build timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	root, command, rootIdentity, err := resolveProjectFile(projectRoot, service.Build.Command, true)
	if err != nil {
		return Verified{}, fmt.Errorf("build command failed: %w", err)
	}
	artifactBefore, err := snapshotOutput(ctx, root, rootIdentity, service.Build.Artifact)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Verified{}, errors.New("build operation timed out")
		}
		return Verified{}, fmt.Errorf("snapshot artifact: %w", err)
	}
	manifestBefore, err := snapshotOutput(ctx, root, rootIdentity, service.Build.Manifest)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Verified{}, errors.New("build operation timed out")
		}
		return Verified{}, fmt.Errorf("snapshot manifest: %w", err)
	}
	result := executor.Run(ctx, opsexec.Request{Program: command, Directory: root, Timeout: timeout})
	if result.Err != nil || result.ExitCode != 0 {
		if result.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Verified{}, errors.New("build command timed out")
		}
		return Verified{}, errors.New("build command failed")
	}
	verified, err := validateContext(ctx, root, rootIdentity, service, target)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Verified{}, errors.New("build operation timed out")
	}
	if err != nil {
		return Verified{}, err
	}
	artifactAfter, err := snapshotOutput(ctx, root, rootIdentity, service.Build.Artifact)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Verified{}, errors.New("build operation timed out")
		}
		return Verified{}, fmt.Errorf("snapshot built artifact: %w", err)
	}
	manifestAfter, err := snapshotOutput(ctx, root, rootIdentity, service.Build.Manifest)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Verified{}, errors.New("build operation timed out")
		}
		return Verified{}, fmt.Errorf("snapshot built manifest: %w", err)
	}
	if (artifactBefore.exists && artifactBefore.equal(artifactAfter)) || (manifestBefore.exists && manifestBefore.equal(manifestAfter)) {
		return Verified{}, errors.New("build outputs are stale")
	}
	return verified, nil
}

func Validate(projectRoot string, service opsconfig.Service, target Target) (Verified, error) {
	return ValidateContext(context.Background(), projectRoot, service, target)
}

func ValidateContext(ctx context.Context, projectRoot string, service opsconfig.Service, target Target) (Verified, error) {
	return validateContext(ctx, projectRoot, nil, service, target)
}

func validateContext(ctx context.Context, projectRoot string, expectedRoot os.FileInfo, service opsconfig.Service, target Target) (Verified, error) {
	if ctx == nil {
		return Verified{}, errors.New("validation context is required")
	}
	if err := ctx.Err(); err != nil {
		return Verified{}, err
	}
	root, artifactPath, rootIdentity, err := resolveProjectFile(projectRoot, service.Build.Artifact, true)
	if err != nil {
		return Verified{}, fmt.Errorf("invalid artifact: %w", err)
	}
	if expectedRoot != nil && !os.SameFile(rootIdentity, expectedRoot) {
		return Verified{}, errors.New("project root identity changed")
	}
	_, manifestPath, manifestRootIdentity, err := resolveProjectFile(root, service.Build.Manifest, true)
	if err != nil {
		return Verified{}, fmt.Errorf("invalid manifest: %w", err)
	}
	if !os.SameFile(rootIdentity, manifestRootIdentity) {
		return Verified{}, errors.New("project root identity changed")
	}
	if artifactPath == manifestPath {
		return Verified{}, errors.New("artifact and manifest paths must differ")
	}

	manifestInfo, err := os.Stat(manifestPath)
	if err != nil {
		return Verified{}, fmt.Errorf("stat manifest: %w", err)
	}
	manifestFile, err := openRegularVerifiedAt(root, rootIdentity, manifestPath, manifestInfo)
	if err != nil {
		return Verified{}, fmt.Errorf("open manifest: %w", err)
	}
	defer manifestFile.Close()
	manifest, err := loadManifest(ctx, manifestFile)
	if err != nil {
		return Verified{}, err
	}
	if err := validateManifest(manifest, service.ID, target); err != nil {
		return Verified{}, err
	}
	artifactInfo, err := os.Stat(artifactPath)
	if err != nil {
		return Verified{}, fmt.Errorf("stat artifact: %w", err)
	}
	artifactFile, err := openRegularVerifiedAt(root, rootIdentity, artifactPath, artifactInfo)
	if err != nil {
		return Verified{}, fmt.Errorf("open artifact: %w", err)
	}
	defer artifactFile.Close()
	digest, size, err := digestFile(ctx, artifactFile)
	if err != nil {
		return Verified{}, fmt.Errorf("digest artifact: %w", err)
	}
	if digest != manifest.SHA256 {
		return Verified{}, errors.New("artifact SHA-256 does not match manifest")
	}
	expandedSize, err := expandedArchiveSize(ctx, artifactFile)
	if err != nil {
		return Verified{}, fmt.Errorf("inspect artifact archive: %w", err)
	}
	return Verified{Manifest: manifest, ArchivePath: artifactPath, Size: size, ExpandedSize: expandedSize, SHA256: digest}, nil
}

func expandedArchiveSize(ctx context.Context, file *os.File) (int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	gz, err := gzip.NewReader(file)
	if err != nil {
		return 0, errors.New("artifact must be a valid gzip stream")
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return 0, errors.New("artifact must be a valid tar archive")
		}
		clean, ok := safeArchivePath(header.Name, header.Typeflag == tar.TypeDir)
		if !ok {
			return 0, errors.New("archive entry path is unsafe")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || total > math.MaxInt64-header.Size {
				return 0, errors.New("archive expanded size is invalid")
			}
			total += header.Size
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return 0, errors.New("artifact entry is truncated")
			}
		case tar.TypeSymlink:
			if header.Size != 0 || !safeArchiveLink(clean, header.Linkname, true) {
				return 0, errors.New("archive symbolic link target is unsafe")
			}
		case tar.TypeLink:
			if header.Size != 0 || !safeArchiveLink(clean, header.Linkname, false) {
				return 0, errors.New("archive hard link target is unsafe")
			}
		default:
			return 0, errors.New("archive entry type is unsafe")
		}
	}
}

func safeArchivePath(name string, directory bool) (string, bool) {
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	clean := path.Clean(name)
	return clean, name != "" && !path.IsAbs(name) && clean == name && clean != "." && clean != ".." && clean != ".agentsetup-artifact.tar.gz" && !strings.HasPrefix(clean, "../") && !hasControl(name)
}

func safeArchiveLink(entry, target string, symbolic bool) bool {
	if target == "" || path.IsAbs(target) || hasControl(target) {
		return false
	}
	resolved := path.Clean(target)
	if symbolic {
		resolved = path.Clean(path.Join(path.Dir(entry), target))
	}
	return resolved != "." && resolved != ".." && !path.IsAbs(resolved) && !strings.HasPrefix(resolved, "../")
}

func resolveProjectFile(projectRoot, relative string, requireRegular bool) (string, string, os.FileInfo, error) {
	if projectRoot == "" {
		return "", "", nil, errors.New("project root is required")
	}
	if hasControl(projectRoot) {
		return "", "", nil, errors.New("project root contains unsupported control characters")
	}
	rootAbs, err := filepath.Abs(projectRoot)
	if err != nil {
		return "", "", nil, err
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", nil, err
	}
	rootInfo, err := os.Stat(rootReal)
	if err != nil || !rootInfo.IsDir() {
		return "", "", nil, errors.New("project root must be a directory")
	}
	clean := filepath.Clean(relative)
	canonical := relative == clean || relative == "."+string(filepath.Separator)+clean
	if strings.TrimSpace(relative) == "" || filepath.IsAbs(relative) || !canonical || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || hasControl(relative) {
		return "", "", nil, errors.New("path must be clean, relative, and contained in the project root")
	}
	candidate := filepath.Join(rootReal, clean)
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", nil, err
	}
	if !contained(rootReal, real) {
		return "", "", nil, errors.New("resolved path escapes the project root")
	}
	if requireRegular {
		info, err := os.Stat(real)
		if err != nil {
			return "", "", nil, err
		}
		if !info.Mode().IsRegular() {
			return "", "", nil, errors.New("path must resolve to a regular file")
		}
	}
	return rootReal, real, rootInfo, nil
}

func contained(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func hasControl(value string) bool {
	for _, r := range value {
		if r <= 0x1f || r == 0x7f {
			return true
		}
	}
	return false
}

func openRegularVerified(path string, expected os.FileInfo) (*os.File, error) {
	root := filepath.Dir(path)
	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	return openRegularVerifiedAt(root, rootInfo, path, expected)
}

func openRootVerified(root string, expected os.FileInfo) (*os.File, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), root)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open returned invalid project root")
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || expected == nil || !os.SameFile(info, expected) {
		file.Close()
		return nil, errors.New("project root identity changed")
	}
	current, err := os.Lstat(root)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
		file.Close()
		return nil, errors.New("project root path identity changed")
	}
	return file, nil
}

func openRegularVerifiedAt(root string, rootIdentity os.FileInfo, path string, expected os.FileInfo) (*os.File, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, errors.New("file path is outside the verified root")
	}
	rootFile, err := openRootVerified(root, rootIdentity)
	if err != nil {
		return nil, err
	}
	rootFD := int(rootFile.Fd())
	currentFD := rootFD
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		nextFD, openErr := unix.Openat(currentFD, part, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if currentFD != rootFD {
			_ = unix.Close(currentFD)
		}
		if openErr != nil {
			_ = rootFile.Close()
			return nil, openErr
		}
		currentFD = nextFD
	}
	fd, err := unix.Openat(currentFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if currentFD != rootFD {
		_ = unix.Close(currentFD)
	}
	_ = rootFile.Close()
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open returned invalid file")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("file descriptor is not a regular file")
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
		file.Close()
		return nil, errors.New("file identity changed while opening")
	}
	if expected != nil && !os.SameFile(info, expected) {
		file.Close()
		return nil, errors.New("file identity does not match validated path")
	}
	return file, nil
}

func loadManifest(ctx context.Context, file *os.File) (Manifest, error) {
	data, err := readLimitedContext(ctx, file, manifestMaxBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if err := rejectDuplicateManifestFields(data); err != nil {
		return Manifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, errors.New("manifest must contain one JSON object")
	}
	return manifest, nil
}

func rejectDuplicateManifestFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("manifest must be a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode manifest: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("manifest field name must be a string")
		}
		if seen[key] {
			return fmt.Errorf("manifest contains duplicate field %q", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode manifest: %w", err)
		}
	}
	return nil
}

func validateManifest(manifest Manifest, service string, target Target) error {
	if hasControl(manifest.Service) || hasControl(manifest.Version) || hasControl(manifest.Commit) || hasControl(manifest.Platform) || hasControl(manifest.Architecture) {
		return errors.New("manifest identity contains unsupported control characters")
	}
	if hasControl(target.Platform) || hasControl(target.Architecture) || strings.TrimSpace(target.Platform) == "" || strings.TrimSpace(target.Architecture) == "" {
		return errors.New("target identity is invalid")
	}
	if manifest.Service != service {
		return errors.New("manifest service does not match")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return errors.New("manifest version is required")
	}
	if !safeVersion.MatchString(manifest.Version) {
		return errors.New("manifest version must be a safe single value")
	}
	if strings.TrimSpace(manifest.Commit) == "" {
		return errors.New("manifest commit is required")
	}
	if manifest.BuiltAt.IsZero() {
		return errors.New("manifest built_at must be valid and non-zero")
	}
	if manifest.Platform != target.Platform || manifest.Architecture != target.Architecture {
		return errors.New("manifest target does not match production host")
	}
	if !lowercaseSHA256.MatchString(manifest.SHA256) {
		return errors.New("manifest sha256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func digestFile(ctx context.Context, file *os.File) (string, int64, error) {
	hash := sha256.New()
	buffer := make([]byte, 32*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		count, err := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
			size += int64(count)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func readLimitedContext(ctx context.Context, file *os.File, limit int64) ([]byte, error) {
	reader := io.LimitReader(file, limit+1)
	var buffer bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, err := reader.Read(chunk)
		if count > 0 {
			_, _ = buffer.Write(chunk[:count])
		}
		if int64(buffer.Len()) > limit {
			return nil, errors.New("manifest exceeds 64 KiB limit")
		}
		if err == io.EOF {
			return buffer.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

type outputSnapshot struct {
	exists bool
	info   os.FileInfo
	digest string
}

func (s outputSnapshot) equal(other outputSnapshot) bool {
	if s.exists != other.exists {
		return false
	}
	if !s.exists {
		return true
	}
	return os.SameFile(s.info, other.info) && s.info.Size() == other.info.Size() && s.info.ModTime().Equal(other.info.ModTime()) && s.digest == other.digest
}

func snapshotOutput(ctx context.Context, root string, rootIdentity os.FileInfo, relative string) (outputSnapshot, error) {
	clean := filepath.Clean(relative)
	canonical := relative == clean || relative == "."+string(filepath.Separator)+clean
	if !canonical || filepath.IsAbs(relative) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || hasControl(relative) {
		return outputSnapshot{}, errors.New("output path is unsafe")
	}
	path := filepath.Join(root, clean)
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return outputSnapshot{}, nil
		}
		return outputSnapshot{}, err
	}
	if !contained(root, real) {
		return outputSnapshot{}, errors.New("output path escapes project root")
	}
	info, err := os.Stat(real)
	if err != nil {
		return outputSnapshot{}, err
	}
	file, err := openRegularVerifiedAt(root, rootIdentity, real, info)
	if err != nil {
		return outputSnapshot{}, err
	}
	defer file.Close()
	digest, _, err := digestFile(ctx, file)
	if err != nil {
		return outputSnapshot{}, err
	}
	return outputSnapshot{exists: true, info: info, digest: digest}, nil
}
