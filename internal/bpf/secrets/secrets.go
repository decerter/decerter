// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"fmt"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" -target amd64 bpf ../../../bpf/secrets/secrets.c -- -I../../../bpf -I../../../bpf/include

const (
	SecretsEventMap bpf.BpfMapName     = 0 // value: "secrets_event_map"
	SecretsMap      bpf.BpfMapName     = 1 // value: "secrets_map"
	SslMap          bpf.BpfMapName     = 2 // value: "ssl_map"
	TgidMap         bpf.BpfMapName     = 3 // value: "tgid_map"
	UidMap          bpf.BpfMapName     = 4 // value: "uid_map"
	StashSsl        bpf.BpfProgramName = 0 // value: "stash_ssl"
	StoreSecrets    bpf.BpfProgramName = 1 // value: "store_secrets"
)

// sharedUidMap and sharedTgidMap share the redirect object's selection maps in run mode, so run and keylog mode pick processes the same way
// in keylog mode they are nil, the secrets object owns uid_map and tgid_map and UpdateSelection fills them; with both empty no process is read
func LoadBpfObjects(offset openssl.Offset, ownTgid uint32, sharedUidMap *ebpf.Map, sharedTgidMap *ebpf.Map) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
	err = rlimit.RemoveMemlock()

	if err != nil {
		err = fmt.Errorf("remove memlock: %w", err)
		return
	}

	spec, loadErr := loadBpf()

	if err = loadErr; err != nil {
		err = fmt.Errorf("load bpf spec: %w", err)
		return
	}

	// the offsets are set before load so the verifier bakes them into the probe
	variables := map[string]any{
		bpfVarOwnTgid:                      ownTgid,
		bpfVarTypeOffset:                   offset.Type,
		bpfVarSslConnectionOffset:          offset.SSLConnection,
		bpfVarVersionOffset:                offset.Version,
		bpfVarClientRandomOffset:           offset.ClientRandom,
		bpfVarSessionOffset:                offset.Session,
		bpfVarMasterKeyOffset:              offset.MasterKey,
		bpfVarMasterKeyLengthOffset:        offset.MasterKeyLength,
		bpfVarSessionCipherOffset:          offset.SessionCipher,
		bpfVarCipherIdOffset:               offset.CipherId,
		bpfVarClientAppTrafficSecretOffset: offset.ClientAppTrafficSecret,
		bpfVarServerAppTrafficSecretOffset: offset.ServerAppTrafficSecret,
		bpfVarHandshakeSecretOffset:        offset.HandshakeSecret,
		bpfVarHandshakeTrafficHashOffset:   offset.HandshakeTrafficHash,
	}

	for name, value := range variables {
		err = spec.Variables[name].Set(value)

		if err != nil {
			err = fmt.Errorf("set %s: %w", name, err)
			return
		}
	}

	options := &ebpf.CollectionOptions{}

	// run mode shares the redirect object's selection maps, so one set of uid/tgid entries drives both objects
	if (sharedUidMap != nil) && (sharedTgidMap != nil) {
		options.MapReplacements = map[string]*ebpf.Map{
			bpfMapUidMap:  sharedUidMap,
			bpfMapTgidMap: sharedTgidMap,
		}
	}

	objs := bpfObjects{}
	err = spec.LoadAndAssign(&objs, options)

	if err != nil {
		err = fmt.Errorf("load bpf objects: %w", err)
		return
	}

	bpfMaps = map[bpf.BpfMapName]*ebpf.Map{
		SecretsEventMap: objs.SecretsEventMap,
		SecretsMap:      objs.SecretsMap,
		SslMap:          objs.SslMap,
		TgidMap:         objs.TgidMap,
		UidMap:          objs.UidMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		StashSsl:     objs.StashSsl,
		StoreSecrets: objs.StoreSecrets,
	}
	closeFunction = objs.Close
	return
}

// keylog mode fills the secrets object's own uid_map and tgid_map, run mode shares the redirect's maps and never calls this
func UpdateSelection(uids []uint32, tgids []uint32, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	for _, uid := range uids {
		err = bpfMaps[UidMap].Update(uid, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s uid %d: %w", bpfMapUidMap, uid, err)
			return
		}
	}

	for _, tgid := range tgids {
		err = bpfMaps[TgidMap].Update(tgid, uint8(1), ebpf.UpdateAny)

		if err != nil {
			err = fmt.Errorf("update %s tgid %d: %w", bpfMapTgidMap, tgid, err)
			return
		}
	}

	return
}

// SymbolHooks are the libssl functions whose return the secrets uprobe reads, SSL_connect and SSL_accept delegate to SSL_do_handshake, the _ex variants carry python's implicit handshake
func SymbolHooks() (symbols []string) {
	symbols = []string{"SSL_do_handshake", "SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"}
	return
}
