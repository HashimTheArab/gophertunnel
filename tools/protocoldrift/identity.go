package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// inspectSource reads the target from the inspected source, without importing it.
func inspectSource(root string) (Manifest, error) {
	var identity Manifest
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "minecraft", "protocol", "info.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		return identity, fmt.Errorf("read source identity: %w", err)
	}
	if file.Name.Name != "protocol" {
		return identity, fmt.Errorf("source info.go must declare package protocol")
	}
	seen := map[string]bool{}
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if name.Name != "CurrentVersion" && name.Name != "CurrentProtocol" {
					continue
				}
				if seen[name.Name] || i >= len(value.Values) {
					return identity, fmt.Errorf("source %s must have one explicit literal value", name.Name)
				}
				seen[name.Name] = true
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok {
					return identity, fmt.Errorf("source %s must be a literal", name.Name)
				}
				switch name.Name {
				case "CurrentVersion":
					if literal.Kind != token.STRING {
						return identity, fmt.Errorf("source CurrentVersion must be a string")
					}
					identity.MinecraftVersion, err = strconv.Unquote(literal.Value)
				case "CurrentProtocol":
					if literal.Kind != token.INT {
						return identity, fmt.Errorf("source CurrentProtocol must be an integer")
					}
					var protocol int64
					protocol, err = strconv.ParseInt(literal.Value, 0, 32)
					identity.ProtocolVersion = int(protocol)
				}
				if err != nil {
					return identity, fmt.Errorf("source %s: %w", name.Name, err)
				}
			}
		}
	}
	if strings.TrimSpace(identity.MinecraftVersion) == "" || identity.ProtocolVersion <= 0 {
		return identity, fmt.Errorf("source info.go must declare a nonempty CurrentVersion and positive CurrentProtocol")
	}
	identity.Source, err = sourceRevision(root)
	return identity, err
}

// sourceRevision labels archives explicitly and marks changes to inspected sources.
func sourceRevision(root string) (string, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	top, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "gophertunnel@unversioned", nil
	}
	topPath, err := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	if err != nil {
		return "", err
	}
	if topPath != root {
		// An archive inside another checkout does not inherit that checkout's identity.
		return "gophertunnel@unversioned", nil
	}
	revision, err := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("read inspected source revision: %w", err)
	}
	status, err := exec.Command("git", "-C", root, "status", "--porcelain", "--untracked-files=all", "--", "minecraft/protocol").Output()
	if err != nil {
		return "", fmt.Errorf("read inspected source status: %w", err)
	}
	label := "gophertunnel@" + strings.TrimSpace(string(revision))
	if len(status) != 0 {
		label += "-dirty"
	}
	return label, nil
}
