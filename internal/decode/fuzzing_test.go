// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"testing"
)

// every context and as over data: no error, no decoder failure, a tree inside the bytes with printable strings only, a summary of bounded size
func fuzzDecodes(state *testing.T, data []byte, contexts []Context, protocols []string) {
	for _, context := range contexts {
		for _, as := range protocols {
			result, err := Decode(data, context, as)

			if err != nil {
				state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
			}

			if problems := shapeErrors(result.Tree, 0, result.Length); (len(problems) > 0) || (result.Error != "") {
				state.Fatalf("Fuzz of decode.Decode failed, as %q, the tree should fit its bytes, problems: %v, error: %s", as, problems, result.Error)
			}

			if len(result.Summary) > (maxSummaryLines+1)*4*maxSummaryBytes {
				state.Fatalf("Fuzz of decode.Decode failed, as %q, the summary should stay small, length: %d", as, len(result.Summary))
			}
		}
	}
}
