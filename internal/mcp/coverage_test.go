// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package mcp

import (
	"net/http"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	specPath string = "../../api/openapi.yaml"
	// an operation with this extension set to false has no tool
	noToolExtension string = "x-decerter-mcp-tool"
)

var (
	// every tool and the operationId of api/openapi.yaml it calls, written out: a new operation needs a line here and a tool
	toolOperations = map[string]string{
		"status":            "getStatus",
		"list_flows":        "listFlows",
		"get_flow":          "getFlow",
		"list_messages":     "listMessages",
		"get_message":       "getMessage",
		"list_exchanges":    "listExchanges",
		"get_exchange":      "getExchange",
		"get_exchange_body": "getExchangeBody",
		"tail_events":       "streamEvents",
		"list_held":         "listHolds",
		"list_rules":        "listRules",
		"export_keylog":     "exportKeylog",
		"export_pcap":       "exportPcap",
		"list_captures":     "listCaptures",
		"download_pcap":     "downloadCapture",
		"set_intercept":     "setIntercept",
		"edit_held":         "editHold",
		"forward_held":      "forwardHold",
		"drop_held":         "dropHold",
		"add_rule":          "addRule",
		"delete_rule":       "deleteRule",
		"start_capture":     "startCapture",
		"stop_capture":      "stopCapture",
	}
	// the operations without a tool, each marked x-decerter-mcp-tool: false in the spec: the live pcapng stream doesn't fit a tool call
	noToolOperations = []string{"streamCapture"}
)

// Test if every operation of api/openapi.yaml has exactly one tool of the server with --allow-write, except those marked x-decerter-mcp-tool: false, every tool has an operation, a GET's tool is a read tool and any other method's tool is not.
func TestCoveragePositive(state *testing.T) {
	loader := openapi3.NewLoader()
	loader.Context = state.Context()
	document, err := loader.LoadFromFile(specPath)

	if err != nil {
		state.Fatalf("Could not load the api spec, error: %s", err.Error())
	}

	methods := map[string]string{}
	marked := []string{}

	for _, pathItem := range document.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			if (operation.OperationID == "") || (methods[operation.OperationID] != "") {
				state.Fatalf("Test of the tool coverage failed, every operation should have its own operationId, %s %q", method, operation.OperationID)
			}

			methods[operation.OperationID] = method

			if isTool, isSet := operation.Extensions[noToolExtension]; isSet && (isTool == false) {
				marked = append(marked, operation.OperationID)
			}
		}
	}

	slices.Sort(marked)

	if !slices.Equal(marked, noToolOperations) {
		state.Fatalf("Test of the tool coverage failed, the operations marked %s: false should be %v, marked: %v", noToolExtension, noToolOperations, marked)
	}

	// the registered tools, read-only or not
	session := connect(state, startFakeAPI(state), state.TempDir(), true)
	isReadOnly := map[string]bool{}

	for tool, toolErr := range session.Tools(state.Context(), nil) {
		if toolErr != nil {
			state.Fatalf("Test of the tool coverage failed, cannot list the tools, error: %s", toolErr.Error())
		}

		isReadOnly[tool.Name] = (tool.Annotations != nil) && tool.Annotations.ReadOnlyHint
	}

	for name := range isReadOnly {
		if _, isMapped := toolOperations[name]; !isMapped {
			state.Errorf("Test of the tool coverage failed, tool %s should call an operation of the api", name)
			return
		}
	}

	tools := map[string][]string{}

	for name, operationID := range toolOperations {
		method, isOperation := methods[operationID]
		readOnly, isRegistered := isReadOnly[name]

		switch {
		case !isOperation:
			state.Errorf("Test of the tool coverage failed, tool %s calls %s, which is no operation of the api", name, operationID)
			return
		case !isRegistered:
			state.Errorf("Test of the tool coverage failed, tool %s for %s should be registered with --allow-write", name, operationID)
			return
		case readOnly != (method == http.MethodGet):
			state.Errorf("Test of the tool coverage failed, tool %s calls %s %s, it should be read-only only for a GET, read-only: %t", name, method, operationID, readOnly)
			return
		}

		tools[operationID] = append(tools[operationID], name)
	}

	for operationID := range methods {
		expected := 1

		if slices.Contains(noToolOperations, operationID) {
			expected = 0
		}

		if len(tools[operationID]) != expected {
			state.Errorf("Test of the tool coverage failed, operation %s should have %d tool, tools: %v", operationID, expected, tools[operationID])
			return
		}
	}
}
