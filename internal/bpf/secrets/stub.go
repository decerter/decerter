// SPDX-License-Identifier: AGPL-3.0-only

// the secrets object is generated for amd64 only (PT_REGS_*), this stub keeps other architectures compiling until the arm64 uprobe build
//go:build !amd64

package secrets

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/decerter/decerter/internal/tlsrecord"
	"github.com/cilium/ebpf"
)

const (
	SecretsEventMap bpf.BpfMapName     = 0 // value: "secrets_event_map"
	SecretsMap      bpf.BpfMapName     = 1 // value: "secrets_map"
	SslMap          bpf.BpfMapName     = 2 // value: "ssl_map"
	TgidMap         bpf.BpfMapName     = 3 // value: "tgid_map"
	UidMap          bpf.BpfMapName     = 4 // value: "uid_map"
	StashSsl        bpf.BpfProgramName = 0 // value: "stash_ssl"
	StoreSecrets    bpf.BpfProgramName = 1 // value: "store_secrets"
)

func CheckSupported() (err error) {
	err = fmt.Errorf("%w: %s", ErrUnsupportedArchitecture, runtime.GOARCH)
	return
}

func LoadBpfObjects(offset openssl.Offset, ownTgid uint32, sharedUidMap *ebpf.Map, sharedTgidMap *ebpf.Map) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
	err = CheckSupported()
	return
}

func UpdateSelection(uids []uint32, tgids []uint32, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	err = CheckSupported()
	return
}

// nothing to read without the uprobe
func ReadKeyLog(ctx context.Context, eventMap *ebpf.Map, writer io.Writer, logger *slog.Logger) {
	logger.Error("Could not read key log", "error", CheckSupported())
}

// no secrets without the uprobe
func Lookup(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (sessionSecrets tlsrecord.Secrets, found bool, err error) {
	err = CheckSupported()
	return
}

// no key log without the uprobe
func LookupKeyLog(clientRandom [32]byte, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (keyLog string, found bool, err error) {
	err = CheckSupported()
	return
}

func SymbolHooks() (symbols []string) {
	symbols = []string{}
	return
}
