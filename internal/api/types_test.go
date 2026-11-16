// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Test if every type of internal/api returns with the expected output: a doc comment of its own, and Backend's says what the server serves, so a type
// put between a comment and its type does not take that comment.
func TestTypeDocsPositive(state *testing.T) {
	files, err := filepath.Glob("*.go")

	if err != nil {
		state.Fatalf("Could not list the files, error: %s", err.Error())
	}

	docs := map[string]string{}

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)

		if parseErr != nil {
			state.Fatalf("Could not parse %s, error: %s", name, parseErr.Error())
		}

		for _, declaration := range file.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)

			if !isGeneral || (general.Tok != token.TYPE) {
				continue
			}

			for _, spec := range general.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				doc := typeSpec.Doc

				if doc == nil {
					doc = general.Doc
				}

				if doc == nil {
					state.Errorf("Test of the types failed, %s has no doc comment, in %s", typeSpec.Name.Name, name)
					continue
				}

				docs[typeSpec.Name.Name] = doc.Text()
			}
		}
	}

	if !strings.HasPrefix(docs["Backend"], "what the server serves") || !strings.HasPrefix(docs["exportWriter"], "the body of a pcap export") {
		state.Errorf("Test of the types failed, Backend and exportWriter should have their own doc comments, Backend: %q, exportWriter: %q", docs["Backend"], docs["exportWriter"])
	}
}
