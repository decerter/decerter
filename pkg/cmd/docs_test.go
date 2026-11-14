// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package cmd

import (
	"fmt"
	"go/version"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decerter/decerter/internal/filter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	// the repository root, seen from pkg/cmd
	repositoryRoot string = "../.."
	fieldsBegin    string = "<!-- fields begin -->\n"
	fieldsEnd      string = "<!-- fields end -->\n"
)

// Test if the decerter --help dump in README.md is the help decerter prints, so the README can't drift from it.
func TestReadmeHelpPositive(state *testing.T) {
	help, err := execute(state, []string{"--help"})

	if err != nil {
		state.Fatalf("Test of the README's help failed, error: %s", err.Error())
	}

	readme, err := os.ReadFile(filepath.Join(repositoryRoot, "README.md"))

	if err != nil {
		state.Fatalf("Test of the README's help failed, error: %s", err.Error())
	}

	expected := "```\n$ decerter --help\n" + help + "```\n"

	if !strings.Contains(string(readme), expected) {
		state.Errorf("Test of the README's help failed, README.md should contain this block, the output of decerter --help:\n%s", expected)
		return
	}
}

// Test if the field table of docs/filter.md is the one decerter help filter prints, built from filter.Fields.
func TestFilterDocsPositive(state *testing.T) {
	page, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "filter.md"))

	if err != nil {
		state.Fatalf("Test of docs/filter.md failed, error: %s", err.Error())
	}

	_, rest, foundBegin := strings.Cut(string(page), fieldsBegin)
	table, _, foundEnd := strings.Cut(rest, fieldsEnd)
	expected := fieldsMarkdown()

	if !foundBegin || !foundEnd || (table != expected) {
		state.Errorf("Test of docs/filter.md failed, the lines between %q and %q should be:\n%s", strings.TrimSpace(fieldsBegin), strings.TrimSpace(fieldsEnd), expected)
		return
	}
}

// Test if every flag of every decerter command is named somewhere in README.md or docs/, so a new flag gets documented.
func TestFlagDocsPositive(state *testing.T) {
	paths, err := filepath.Glob(filepath.Join(repositoryRoot, "docs", "*.md"))

	if err != nil {
		state.Fatalf("Test of the flag docs failed, error: %s", err.Error())
	}

	var docs strings.Builder

	for _, path := range append(paths, filepath.Join(repositoryRoot, "README.md")) {
		content, readErr := os.ReadFile(path)

		if err = readErr; err != nil {
			state.Fatalf("Test of the flag docs failed, error: %s", err.Error())
		}

		docs.Write(content)
	}

	commands := []*cobra.Command{rootCmd}

	for len(commands) > 0 {
		command := commands[0]
		commands = append(commands[1:], command.Commands()...)

		command.Flags().VisitAll(func(flag *pflag.Flag) {
			if (flag.Name == "help") || (flag.Name == "version") || (command.Name() == "completion") || (command.HasParent() && (command.Parent().Name() == "completion")) {
				return
			}

			if !strings.Contains(docs.String(), "--"+flag.Name) {
				state.Errorf("Test of the flag docs failed, --%s of %s is not in README.md or docs/", flag.Name, command.CommandPath())
			}
		})
	}
}

// Test if go.mod pins a toolchain that is at least its go version, and every workflow takes Go from go.mod, so CI and local builds use the same Go and
// release checksums match.
func TestToolchainPositive(state *testing.T) {
	goMod, err := os.ReadFile(filepath.Join(repositoryRoot, "go.mod"))

	if err != nil {
		state.Fatalf("Test of the toolchain failed, error: %s", err.Error())
	}

	goVersion, toolchain := "", ""

	for line := range strings.Lines(string(goMod)) {
		fields := strings.Fields(line)

		switch {
		case (len(fields) == 2) && (fields[0] == "go"):
			goVersion = "go" + fields[1]
		case (len(fields) == 2) && (fields[0] == "toolchain"):
			toolchain = fields[1]
		default:
		}
	}

	if (goVersion == "") || !version.IsValid(toolchain) || (version.Compare(toolchain, goVersion) < 0) || (version.Lang(toolchain) != version.Lang(goVersion)) {
		state.Errorf("Test of the toolchain failed, go.mod should name a toolchain of its go version's language, at least that version, go: %q, toolchain: %q", goVersion, toolchain)
		return
	}

	workflows, err := filepath.Glob(filepath.Join(repositoryRoot, ".github", "workflows", "*.yml"))

	if (err != nil) || (len(workflows) == 0) {
		state.Fatalf("Test of the toolchain failed, no workflows, error: %v", err)
	}

	for _, path := range workflows {
		content, readErr := os.ReadFile(path)

		if err = readErr; err != nil {
			state.Fatalf("Test of the toolchain failed, error: %s", err.Error())
		}

		if strings.Contains(string(content), "go-version:") {
			state.Errorf("Test of the toolchain failed, %s should take Go from go.mod with go-version-file, not go-version", path)
		}
	}
}

// the field table of docs/filter.md: name, type, one or several values, source, kernel map
func fieldsMarkdown() (table string) {
	var lines strings.Builder
	lines.WriteString("| Field | Type | Values | Source | Kernel map |\n|---|---|---|---|---|\n")

	for _, info := range filter.Fields() {
		values := "one"

		if info.IsMulti {
			values = "several"
		}

		kernelMap := ""

		if info.Pushdown != "" {
			kernelMap = "`" + info.Pushdown + "`"
		}

		fmt.Fprintf(&lines, "| `%s` | %s | %s | %s | %s |\n", info.Name, info.Type, values, info.Source, kernelMap)
	}

	table = lines.String()
	return
}
