// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package decode

import (
	"testing"
)

// every context and as over data: no error, no decoder failure, a tree inside the bytes with printable strings only, within the limits of its strings and
// its summary
func fuzzDecodes(state *testing.T, data []byte, contexts []Context, protocols []string) {
	for _, context := range contexts {
		for _, as := range protocols {
			result, err := Decode(data, context, as)

			if err != nil {
				state.Fatalf("Fuzz of decode.Decode failed, it should take any bytes, error: %s", err.Error())
			}

			if problems := resultProblems(result); len(problems) > 0 {
				state.Fatalf("Fuzz of decode.Decode failed, as %q, the tree should fit its bytes, problems: %v", as, problems)
			}
		}
	}
}
