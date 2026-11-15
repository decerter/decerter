// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// committed objects of the repository: two byte orders of one source, and objects of two sources
	captureLittle  string = "../../internal/bpf/capture/bpf_bpfel.o"
	captureBig     string = "../../internal/bpf/capture/bpf_bpfeb.o"
	redirectLittle string = "../../internal/bpf/redirect/bpf_bpfel.o"
	secretsLittle  string = "../../internal/bpf/secrets/bpf_x86_bpfel.o"
)

// a copy of the object at source in the test's directory, the same content at another path
func copyObject(state *testing.T, source string) (path string) {
	data, err := os.ReadFile(source)

	if err != nil {
		state.Fatalf("Test of bpfdrift failed, cannot read %s, error: %s", source, err.Error())
	}

	path = filepath.Join(state.TempDir(), filepath.Base(source))
	err = os.WriteFile(path, data, 0o600)

	if err != nil {
		state.Fatalf("Test of bpfdrift failed, cannot write %s, error: %s", path, err.Error())
	}

	return
}

// Test if bpfdrift.compare returns with the expected output: an object and its copy are the same, objects of another byte order or another source differ at their first differing line.
func TestComparePositive(state *testing.T) {
	positiveCases := []struct {
		Name      string
		Committed string
		Generated string
		Expected  string
	}{
		{Name: "the copy of capture", Committed: captureLittle, Generated: copyObject(state, captureLittle), Expected: ""},
		{Name: "the copy of redirect", Committed: redirectLittle, Generated: copyObject(state, redirectLittle), Expected: ""},
		{Name: "the copy of secrets", Committed: secretsLittle, Generated: copyObject(state, secretsLittle), Expected: ""},
		{Name: "another byte order", Committed: captureLittle, Generated: captureBig, Expected: `line 1: committed "byte order LittleEndian", generated "byte order BigEndian"`},
		{Name: "another source", Committed: captureLittle, Generated: redirectLittle, Expected: "line 2: committed "},
	}

	for _, positive := range positiveCases {
		difference, err := compare(positive.Committed, positive.Generated)

		if (err != nil) || ((positive.Expected == "") && (difference != "")) || !strings.HasPrefix(difference, positive.Expected) {
			state.Errorf("Test of bpfdrift.compare function failed, %s, difference should start with %q, difference: %q, error: %v", positive.Name, positive.Expected, difference, err)
			return
		}
	}
}

// Test if bpfdrift.compare returns with the expected errors: a committed or generated object that is missing or not an ELF file.
func TestCompareNegative(state *testing.T) {
	missing := filepath.Join(state.TempDir(), "missing.o")
	broken := filepath.Join(state.TempDir(), "broken.o")
	err := os.WriteFile(broken, []byte("not an object"), 0o600)

	if err != nil {
		state.Fatalf("Test of bpfdrift.compare failed, cannot write %s, error: %s", broken, err.Error())
	}

	negativeCases := []struct {
		Name      string
		Committed string
		Generated string
		Missing   bool
	}{
		{Name: "missing committed object", Committed: missing, Generated: captureLittle, Missing: true},
		{Name: "missing generated object", Committed: captureLittle, Generated: missing, Missing: true},
		{Name: "broken committed object", Committed: broken, Generated: captureLittle, Missing: false},
		{Name: "broken generated object", Committed: captureLittle, Generated: broken, Missing: false},
	}

	for _, negative := range negativeCases {
		difference, err := compare(negative.Committed, negative.Generated)

		if (err == nil) || (difference != "") || (errors.Is(err, fs.ErrNotExist) != negative.Missing) {
			state.Errorf("Test of bpfdrift.compare function failed, %s, error should be set (missing %v), difference: %q, error: %v", negative.Name, negative.Missing, difference, err)
			return
		}
	}
}

// Test if bpfdrift.lineAt returns with the expected output: the line at an index, a marker past the end.
func TestLineAtPositive(state *testing.T) {
	lines := []string{"first", "second"}
	positiveCases := []struct {
		Index    int
		Expected string
	}{
		{Index: 0, Expected: "first"},
		{Index: 1, Expected: "second"},
		{Index: 2, Expected: "(end of object)"},
	}

	for _, positive := range positiveCases {
		line := lineAt(lines, positive.Index)

		if line != positive.Expected {
			state.Errorf("Test of bpfdrift.lineAt function failed, index %d, line should be %q, line: %q", positive.Index, positive.Expected, line)
			return
		}
	}
}

// Test if bpfdrift.describe returns with the expected output: the byte order, the maps, variables, programs with source lines and CO-RE relocations, and the BTF types of an object.
func TestDescribePositive(state *testing.T) {
	description, err := describe(secretsLittle)

	if err != nil {
		state.Fatalf("Test of bpfdrift.describe function failed, error: %s", err.Error())
	}

	for _, expected := range []string{"byte order LittleEndian\n", "\nmap ", "\n\tkey ", "\nvariable ", "\nprogram ", "\n\t; ", " func=", "\ntype "} {
		if !strings.Contains(description, expected) {
			state.Errorf("Test of bpfdrift.describe function failed, the description should contain %q, description starts with: %.2000s", expected, description)
			return
		}
	}

	// the local type id moves with the BTF order, it is cut from the relocations
	if strings.Contains(description, "local_id=") {
		state.Errorf("Test of bpfdrift.describe function failed, the description should have no local type ids")
		return
	}
}
