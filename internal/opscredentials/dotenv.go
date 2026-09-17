package opscredentials

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/sys/unix"
)

const maxDotenvSize = 64 * 1024

func sameDotenvStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid &&
		a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

var dotenvAssignment = regexp.MustCompile(`^(?:export[ ]+)?([A-Za-z_][A-Za-z0-9_]*)[ ]*=[ ]*(.*)$`)

func parseStrictDotenv(data []byte) (map[string]string, error) {
	invalid := func() (map[string]string, error) { return nil, errors.New("CF_CREDENTIAL_FILE_SYNTAX") }
	if len(data) > maxDotenvSize {
		return nil, errors.New("CF_CREDENTIAL_FILE_TOO_LARGE")
	}
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	for _, b := range normalized {
		if (b < 32 && b != '\n') || b == 127 {
			return invalid()
		}
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(normalized), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, "$\x60") {
			return invalid()
		}
		match := dotenvAssignment.FindStringSubmatch(line)
		if match == nil {
			return invalid()
		}
		name := match[1]
		if _, exists := values[name]; exists {
			return invalid()
		}
		parsed, err := godotenv.Parse(strings.NewReader(line + "\n"))
		if err != nil || len(parsed) != 1 {
			return invalid()
		}
		value, exists := parsed[name]
		if !exists || strings.ContainsAny(value, "\r\n\x00") {
			return invalid()
		}
		values[name] = value
	}
	return values, nil
}

// afterOpen is a package-local deterministic mutation seam; production passes nil.
func readDotenv(path string, expectedUID int, afterOpen func()) (map[string]string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("CF_CREDENTIAL_FILE_OPEN")
	}
	file := os.NewFile(uintptr(fd), "agentops-credentials")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("CF_CREDENTIAL_FILE_OPEN")
	}
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		return nil, errors.New("CF_CREDENTIAL_FILE_STAT")
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || int(before.Uid) != expectedUID {
		return nil, errors.New("CF_CREDENTIAL_FILE_SECURITY")
	}
	if before.Size < 0 || before.Size > maxDotenvSize {
		return nil, errors.New("CF_CREDENTIAL_FILE_TOO_LARGE")
	}
	if afterOpen != nil {
		afterOpen()
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDotenvSize+1))
	defer clear(data)
	if err != nil {
		return nil, errors.New("CF_CREDENTIAL_FILE_READ")
	}
	if len(data) > maxDotenvSize {
		return nil, errors.New("CF_CREDENTIAL_FILE_TOO_LARGE")
	}
	check := func() bool {
		var descriptor, named unix.Stat_t
		return unix.Fstat(fd, &descriptor) == nil && unix.Lstat(path, &named) == nil &&
			sameDotenvStat(before, descriptor) && sameDotenvStat(before, named)
	}
	if !check() {
		return nil, errors.New("CF_CREDENTIAL_FILE_CHANGED")
	}
	values, err := parseStrictDotenv(data)
	if err != nil {
		return nil, err
	}
	if !check() {
		return nil, errors.New("CF_CREDENTIAL_FILE_CHANGED")
	}
	return values, nil
}
