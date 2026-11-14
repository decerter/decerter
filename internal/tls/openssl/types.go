// SPDX-License-Identifier: AGPL-3.0-only

package openssl

// one libssl the secrets uprobes attach to: Libssl is the path they attach to (it may lead through /proc/<pid>/root into a container), Libcrypto the
// library next to it with the version string; Version and Offset are set by Inspect
type Library struct {
	Libssl    string
	Libcrypto string
	Version   string
	Offset    Offset
}
