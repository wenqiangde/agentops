package opscloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

var (
	accountIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	workerPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	versionPattern   = regexp.MustCompile(`^(?:wrangler\s+)?[0-9]+(?:\.[0-9]+){1,2}(?:[-+][0-9A-Za-z.-]+)?$`)
)

type Request struct {
	SourcePath     string
	Worker         string
	AccountID      string
	WranglerConfig string
	Timeout        time.Duration
}

type Evidence struct {
	WranglerVersion string
	Worker          string
	AccountID       string
	WranglerConfig  string
}

func Inspect(ctx context.Context, executor opsexec.Executor, request Request) (Evidence, error) {
	if ctx == nil {
		return Evidence{}, errors.New("Cloudflare preflight context is required")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	if executor == nil {
		return Evidence{}, errors.New("Cloudflare preflight executor is required")
	}
	if err := validateRequest(request); err != nil {
		return Evidence{}, err
	}
	if err := validateProjectFiles(request); err != nil {
		return Evidence{}, err
	}

	versionResult := executor.Run(ctx, opsexec.Request{
		Program: "node_modules/.bin/wrangler", Args: []string{"--version"},
		Directory: request.SourcePath, Timeout: request.Timeout,
	})
	version, err := checkedVersion(versionResult)
	if err != nil {
		return Evidence{}, err
	}
	whoamiResult := executor.Run(ctx, opsexec.Request{
		Program:   "node_modules/.bin/wrangler",
		Args:      []string{"whoami", "--account", request.AccountID, "--json"},
		Directory: request.SourcePath, Timeout: request.Timeout,
	})
	if err := checkAccountMembership(whoamiResult, request.AccountID); err != nil {
		return Evidence{}, err
	}
	return Evidence{
		WranglerVersion: version,
		Worker:          request.Worker, AccountID: request.AccountID,
		WranglerConfig: request.WranglerConfig,
	}, nil
}

func validateRequest(request Request) error {
	if request.SourcePath == "" || !filepath.IsAbs(request.SourcePath) || filepath.Clean(request.SourcePath) != request.SourcePath {
		return errors.New("source path must be a canonical absolute path")
	}
	if !workerPattern.MatchString(request.Worker) {
		return errors.New("Cloudflare Worker name is invalid")
	}
	if !accountIDPattern.MatchString(request.AccountID) {
		return errors.New("Cloudflare account ID is invalid")
	}
	config := filepath.Clean(request.WranglerConfig)
	if request.WranglerConfig == "" || !utf8.ValidString(request.WranglerConfig) || filepath.IsAbs(request.WranglerConfig) || config != request.WranglerConfig || config == "." || config == ".." || strings.HasPrefix(config, ".."+string(filepath.Separator)) {
		return errors.New("Wrangler config must be a clean relative path")
	}
	return nil
}

func validateProjectFiles(request Request) error {
	if err := requireDirectory(request.SourcePath, "source path"); err != nil {
		return err
	}
	if !hasLockfile(request.SourcePath) {
		return errors.New("project lockfile is required")
	}
	packageJSON, err := readRegularFile(filepath.Join(request.SourcePath, "package.json"), "package.json")
	if err != nil {
		return err
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(packageJSON, &manifest) != nil {
		return errors.New("package.json is malformed")
	}
	if manifest.Dependencies["wrangler"] == "" && manifest.DevDependencies["wrangler"] == "" {
		return errors.New("package.json must declare Wrangler")
	}
	wranglerPath := filepath.Join(request.SourcePath, "node_modules", ".bin", "wrangler")
	if err := requireProjectExecutable(request.SourcePath, wranglerPath); err != nil {
		return err
	}
	configContent, err := readContainedRegularFile(request.SourcePath, filepath.Join(request.SourcePath, request.WranglerConfig), "Wrangler config")
	if err != nil {
		return err
	}
	config, err := parseWranglerConfig(configContent)
	if err != nil {
		return err
	}
	if config.Name != request.Worker {
		return errors.New("Cloudflare Worker name does not match Wrangler config")
	}
	if config.AccountID != request.AccountID {
		return errors.New("Cloudflare account ID does not match Wrangler config")
	}
	return nil
}

func requireDirectory(path, label string) error {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s is unavailable", label)
	}
	return nil
}

func hasLockfile(root string) bool {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func requireProjectExecutable(source, path string) error {
	resolvedSource, sourceErr := filepath.EvalSymlinks(source)
	resolvedPath, pathErr := filepath.EvalSymlinks(path)
	info, statErr := os.Stat(resolvedPath)
	nodeModules := filepath.Join(resolvedSource, "node_modules")
	if sourceErr != nil || pathErr != nil || statErr != nil || !pathWithin(nodeModules, resolvedPath) || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("project-local Wrangler executable is unavailable; run npm ci")
	}
	return nil
}

func readContainedRegularFile(root, path, label string) ([]byte, error) {
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	resolvedPath, pathErr := filepath.EvalSymlinks(path)
	if rootErr != nil || pathErr != nil || !pathWithin(resolvedRoot, resolvedPath) {
		return nil, fmt.Errorf("%s is unavailable", label)
	}
	return readRegularFile(resolvedPath, label)
}

func readRegularFile(path, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is unavailable", label)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s could not be read", label)
	}
	return content, nil
}

type wranglerConfig struct {
	Name      string `json:"name"`
	AccountID string `json:"account_id"`
}

func parseWranglerConfig(content []byte) (wranglerConfig, error) {
	clean, err := stripJSONComments(content)
	if err != nil {
		return wranglerConfig{}, errors.New("Wrangler config is malformed")
	}
	clean, err = stripJSONTrailingCommas(clean)
	if err != nil {
		return wranglerConfig{}, errors.New("Wrangler config is malformed")
	}
	var config wranglerConfig
	if json.Unmarshal(clean, &config) != nil || config.Name == "" || config.AccountID == "" {
		return wranglerConfig{}, errors.New("Wrangler config is malformed")
	}
	return config, nil
}

func stripJSONTrailingCommas(content []byte) ([]byte, error) {
	var output bytes.Buffer
	inString := false
	escaped := false
	for index := 0; index < len(content); index++ {
		current := content[index]
		if inString {
			output.WriteByte(current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			output.WriteByte(current)
			continue
		}
		if current == ',' {
			next := index + 1
			for next < len(content) && (content[next] == ' ' || content[next] == '\t' || content[next] == '\r' || content[next] == '\n') {
				next++
			}
			if next < len(content) && (content[next] == '}' || content[next] == ']') {
				continue
			}
		}
		output.WriteByte(current)
	}
	if inString {
		return nil, errors.New("unterminated string")
	}
	return output.Bytes(), nil
}

func stripJSONComments(content []byte) ([]byte, error) {
	var output bytes.Buffer
	inString := false
	escaped := false
	for index := 0; index < len(content); index++ {
		current := content[index]
		if inString {
			output.WriteByte(current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			output.WriteByte(current)
			continue
		}
		if current == '/' && index+1 < len(content) {
			next := content[index+1]
			if next == '/' {
				index += 2
				for index < len(content) && content[index] != '\n' {
					index++
				}
				output.WriteByte('\n')
				continue
			}
			if next == '*' {
				index += 2
				for index+1 < len(content) && !(content[index] == '*' && content[index+1] == '/') {
					index++
				}
				if index+1 >= len(content) {
					return nil, errors.New("unterminated comment")
				}
				index++
				continue
			}
		}
		output.WriteByte(current)
	}
	if inString {
		return nil, errors.New("unterminated string")
	}
	return output.Bytes(), nil
}

func checkedVersion(result opsexec.Result) (string, error) {
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return "", errors.New("project-local Wrangler version check failed")
	}
	version := strings.TrimSpace(result.Stdout)
	if !versionPattern.MatchString(version) {
		return "", errors.New("project-local Wrangler returned an invalid version")
	}
	return strings.TrimPrefix(version, "wrangler "), nil
}

func checkAccountMembership(result opsexec.Result, accountID string) error {
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return errors.New("Cloudflare authentication check failed")
	}
	var payload struct {
		Accounts []struct {
			ID        string `json:"id"`
			AccountID string `json:"accountId"`
		} `json:"accounts"`
	}
	if json.Unmarshal([]byte(result.Stdout), &payload) != nil {
		return errors.New("Cloudflare authentication response is malformed")
	}
	for _, account := range payload.Accounts {
		if account.ID == accountID || account.AccountID == accountID {
			return nil
		}
	}
	return errors.New("not authenticated for configured Cloudflare account")
}
