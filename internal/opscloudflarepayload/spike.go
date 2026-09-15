package opscloudflarepayload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type Payload struct {
	files  map[string][]byte
	sha256 string
}

type Transport interface {
	Send(context.Context, Payload) error
}

func (p Payload) File(name string) ([]byte, bool) {
	content, ok := p.files[name]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), content...), true
}

func (p Payload) SHA256() string {
	return p.sha256
}

func Deliver(ctx context.Context, payload Payload, transport Transport) error {
	if ctx == nil || transport == nil || len(payload.files) == 0 || payload.sha256 == "" {
		return errors.New("Cloudflare frozen payload delivery is invalid")
	}
	return transport.Send(ctx, payload.clone())
}

func (p Payload) clone() Payload {
	files := make(map[string][]byte, len(p.files))
	for name, content := range p.files {
		files[name] = append([]byte(nil), content...)
	}
	return Payload{files: files, sha256: p.sha256}
}

func Capture(root string, paths []string) (Payload, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(resolvedRoot) {
		return Payload{}, errors.New("Cloudflare payload root is unavailable")
	}
	rootFD, err := unix.Open(resolvedRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Payload{}, errors.New("Cloudflare payload root is unavailable")
	}
	defer unix.Close(rootFD)

	names := append([]string(nil), paths...)
	sort.Strings(names)
	files := make(map[string][]byte, len(names))
	digest := sha256.New()
	for _, name := range names {
		clean := filepath.Clean(name)
		if name == "" || filepath.IsAbs(name) || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return Payload{}, errors.New("Cloudflare payload path is invalid")
		}
		if _, exists := files[name]; exists {
			return Payload{}, errors.New("Cloudflare payload paths must be unique")
		}
		content, err := readRelativeFile(rootFD, clean)
		if err != nil {
			return Payload{}, err
		}
		files[name] = append([]byte(nil), content...)
		fmt.Fprintf(digest, "%s\x00%d\x00", filepath.ToSlash(name), len(content))
		_, _ = digest.Write(content)
		_, _ = digest.Write([]byte{0})
	}
	return Payload{files: files, sha256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func readRelativeFile(rootFD int, relative string) ([]byte, error) {
	components := strings.Split(relative, string(filepath.Separator))
	directoryFD, err := unix.Dup(rootFD)
	if err != nil {
		return nil, errors.New("Cloudflare payload file could not be opened")
	}
	defer func() {
		if directoryFD >= 0 {
			unix.Close(directoryFD)
		}
	}()
	for _, component := range components[:len(components)-1] {
		next, err := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, errors.New("Cloudflare payload path is unavailable")
		}
		unix.Close(directoryFD)
		directoryFD = next
	}
	fd, err := unix.Openat(directoryFD, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Cloudflare payload file is unavailable")
	}
	file := os.NewFile(uintptr(fd), relative)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("Cloudflare payload input must be a regular file")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.New("Cloudflare payload file could not be read")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("Cloudflare payload file changed during capture")
	}
	return content, nil
}
