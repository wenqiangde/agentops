package opsconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(root string) (Inventory, []Issue) {
	inv := Inventory{Services: map[string]Service{}, Hosts: map[string]Host{}}
	var issues []Issue

	loadSingle(filepath.Join(root, "hosts.yaml"), "hosts.yaml", &issues, func(data []byte) error {
		var file HostsFile
		if err := decodeStrict(data, &file); err != nil {
			return err
		}
		hostIssues := validateHosts(file)
		issues = append(issues, hostIssues...)
		if len(hostIssues) == 0 {
			inv.Hosts = file.Hosts
			if inv.Hosts == nil {
				inv.Hosts = map[string]Host{}
			}
		}
		return nil
	})

	loadSingle(filepath.Join(root, "policies.yaml"), "policies.yaml", &issues, func(data []byte) error {
		var policies Policies
		if err := decodeStrict(data, &policies); err != nil {
			return err
		}
		policyIssues := validatePolicies(policies)
		issues = append(issues, policyIssues...)
		if len(policyIssues) == 0 {
			inv.Policies = policies
		}
		return nil
	})

	serviceFiles, err := filepath.Glob(filepath.Join(root, "services", "*.yaml"))
	if err != nil {
		issues = append(issues, Issue{File: "services", Message: err.Error()})
	}
	sort.Strings(serviceFiles)
	services := make([]Service, 0, len(serviceFiles))
	for _, filename := range serviceFiles {
		rel := filepath.ToSlash(filepath.Join("services", filepath.Base(filename)))
		data, err := os.ReadFile(filename)
		if err != nil {
			issues = append(issues, Issue{File: rel, Message: err.Error()})
			continue
		}
		if issue := findSecretValue(data); issue != nil {
			issue.File = rel
			issues = append(issues, *issue)
			continue
		}
		var service Service
		if err := decodeStrict(data, &service); err != nil {
			issues = append(issues, decodeIssue(rel, err))
			continue
		}
		service.SourceFile = rel
		services = append(services, service)
	}

	issues = append(issues, validateServices(services, inv.Hosts)...)
	invalidFiles := make(map[string]bool)
	for _, issue := range issues {
		invalidFiles[issue.File] = true
	}
	for _, service := range services {
		if !invalidFiles[service.SourceFile] {
			inv.Services[service.ID] = service
		}
	}
	sortIssues(issues)
	return inv, issues
}

func decodeIssue(file string, err error) Issue {
	message := err.Error()
	const marker = "field "
	if start := strings.Index(message, marker); start >= 0 {
		fieldStart := start + len(marker)
		if end := strings.Index(message[fieldStart:], " not found"); end >= 0 {
			return Issue{File: file, Field: message[fieldStart : fieldStart+end], Message: message}
		}
	}
	return Issue{File: file, Message: message}
}

func loadSingle(path, label string, issues *[]Issue, load func([]byte) error) {
	data, err := os.ReadFile(path)
	if err != nil {
		*issues = append(*issues, Issue{File: label, Message: err.Error()})
		return
	}
	if issue := findSecretValue(data); issue != nil {
		issue.File = label
		*issues = append(*issues, *issue)
		return
	}
	if err := load(data); err != nil {
		*issues = append(*issues, decodeIssue(label, err))
	}
}

func decodeStrict(data []byte, value any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("decode YAML: multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return fmt.Errorf("decode trailing YAML: %w", err)
	}
	return nil
}

func findSecretValue(data []byte) *Issue {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil
	}
	var walk func(*yaml.Node, string, bool) *Issue
	walk = func(node *yaml.Node, path string, planning bool) *Issue {
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				field := key.Value
				childPath := field
				if path != "" {
					childPath = path + "." + field
				}
				childPlanning := planning || field == "futureResources"
				if !childPlanning && isSecretField(field) && hasConfiguredValue(value) {
					return &Issue{Field: childPath, Message: "secret value is not allowed; use a secret reference"}
				}
				if issue := walk(value, childPath, childPlanning); issue != nil {
					return issue
				}
			}
		} else {
			for _, child := range node.Content {
				if issue := walk(child, path, planning); issue != nil {
					return issue
				}
			}
		}
		return nil
	}
	return walk(&document, "", false)
}

func isSecretField(field string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(field, "-", "_"))
	for _, marker := range []string{"password", "secret", "token", "private_key"} {
		if strings.Contains(normalized, marker) {
			return field != "secretKeys"
		}
	}
	return false
}

func hasConfiguredValue(node *yaml.Node) bool {
	return node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) != ""
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		if issues[i].Field != issues[j].Field {
			return issues[i].Field < issues[j].Field
		}
		return issues[i].Message < issues[j].Message
	})
}
