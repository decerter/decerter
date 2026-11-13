// SPDX-License-Identifier: AGPL-3.0-only

// the secrets object is generated for amd64 and arm64 (PT_REGS_*), other architectures get stub.go
//go:build amd64 || arm64

package secrets

import (
	"fmt"

	"github.com/decerter/decerter/internal/bpf"
	"github.com/decerter/decerter/internal/tls/boringssl"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag -mcpu=v4 $BPF_CFLAGS" -target amd64,arm64 bpf ../../../bpf/secrets/secrets.c -- -I../../../bpf -I../../../bpf/include

const (
	LayoutErrorMap     bpf.BpfMapName     = 0 // value: "layout_error_map"
	PartialSecretsMap  bpf.BpfMapName     = 1 // value: "partial_secrets_map"
	SecretsEventMap    bpf.BpfMapName     = 2 // value: "secrets_event_map"
	SecretsMap         bpf.BpfMapName     = 3 // value: "secrets_map"
	SecretsScratchMap  bpf.BpfMapName     = 4 // value: "secrets_scratch_map"
	SslMap             bpf.BpfMapName     = 5 // value: "ssl_map"
	TgidMap            bpf.BpfMapName     = 6 // value: "tgid_map"
	UidMap             bpf.BpfMapName     = 7 // value: "uid_map"
	BoringsslLayoutMap bpf.BpfMapName     = 8 // value: "boringssl_layout_map"
	LogSecret          bpf.BpfProgramName = 0 // value: "log_secret"
	StashSsl           bpf.BpfProgramName = 1 // value: "stash_ssl"
	StoreSecrets       bpf.BpfProgramName = 2 // value: "store_secrets"
)

// the uprobe is built for this architecture, stub.go returns ErrUnsupportedArchitecture
func CheckSupported() (err error) {
	return
}

// one object holds the OpenSSL programs (stash_ssl, store_secrets) and the BoringSSL one (log_secret); the OpenSSL offsets are set before load, they stay zero and
// its programs are never attached when BoringSSL is hooked; the BoringSSL offsets are per library in boringssl_layout_map (SetBoringsslLayout), so Conscrypt and
// every Flutter app can be hooked at once
// sharedUidMap and sharedTgidMap share the redirect object's selection maps in run mode, so run and keylog mode pick processes the same way
// in keylog mode they are nil, the secrets object owns uid_map and tgid_map and UpdateSelection fills them; with both empty no process is read
func LoadBpfObjects(opensslOffset openssl.Offset, ownTgid uint32, sharedUidMap *ebpf.Map, sharedTgidMap *ebpf.Map) (bpfMaps map[bpf.BpfMapName]*ebpf.Map, bpfPrograms map[bpf.BpfProgramName]*ebpf.Program, closeFunction func() error, err error) {
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
	hasType := uint32(0)

	if opensslOffset.HasType {
		hasType = 1
	}

	variables := map[string]any{
		bpfVarOwnTgid:                      ownTgid,
		bpfVarHasType:                      hasType,
		bpfVarTypeOffset:                   opensslOffset.Type,
		bpfVarSslConnectionOffset:          opensslOffset.SSLConnection,
		bpfVarVersionOffset:                opensslOffset.Version,
		bpfVarClientRandomOffset:           opensslOffset.ClientRandom,
		bpfVarSessionOffset:                opensslOffset.Session,
		bpfVarMasterKeyOffset:              opensslOffset.MasterKey,
		bpfVarMasterKeyLengthOffset:        opensslOffset.MasterKeyLength,
		bpfVarSessionCipherOffset:          opensslOffset.SessionCipher,
		bpfVarCipherIdOffset:               opensslOffset.CipherId,
		bpfVarClientAppTrafficSecretOffset: opensslOffset.ClientAppTrafficSecret,
		bpfVarServerAppTrafficSecretOffset: opensslOffset.ServerAppTrafficSecret,
		bpfVarHandshakeSecretOffset:        opensslOffset.HandshakeSecret,
		bpfVarHandshakeTrafficHashOffset:   opensslOffset.HandshakeTrafficHash,
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
		LayoutErrorMap:     objs.LayoutErrorMap,
		PartialSecretsMap:  objs.PartialSecretsMap,
		SecretsEventMap:    objs.SecretsEventMap,
		SecretsMap:         objs.SecretsMap,
		SecretsScratchMap:  objs.SecretsScratchMap,
		SslMap:             objs.SslMap,
		TgidMap:            objs.TgidMap,
		UidMap:             objs.UidMap,
		BoringsslLayoutMap: objs.BoringsslLayoutMap,
	}
	bpfPrograms = map[bpf.BpfProgramName]*ebpf.Program{
		LogSecret:    objs.LogSecret,
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

// the BoringSSL offsets of the library whose ssl_log_secret uprobe gets index as its attach cookie, set before the uprobe is attached
func SetBoringsslLayout(index uint32, offset boringssl.Offset, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (err error) {
	versionInS3 := uint32(0)

	if offset.VersionInS3 {
		versionInS3 = 1
	}

	layout := bpfBoringsslLayout{
		VersionOffset:      offset.Version,
		S3Offset:           offset.S3,
		ClientRandomOffset: offset.ClientRandom,
		VersionInS3:        versionInS3,
		Padding:            0,
	}
	err = bpfMaps[BoringsslLayoutMap].Update(index, layout, ebpf.UpdateExist)

	if err != nil {
		err = fmt.Errorf("update %s index %d: %w", bpfMapBoringsslLayoutMap, index, err)
		return
	}

	return
}

// how many BoringSSL libraries can be hooked at once, the size of boringssl_layout_map
func BoringsslLayouts(bpfMaps map[bpf.BpfMapName]*ebpf.Map) (count uint32) {
	count = bpfMaps[BoringsslLayoutMap].MaxEntries()
	return
}

// the ssl_log_secret calls the uprobe with the attach cookie index rejected because the version it read does not fit the label, err wraps ErrLayoutMismatch with the last one when there were any
// such a library has another BoringSSL layout than its offsets: a Conscrypt APEX updated through Play apart from the release, a Flutter engine built differently
func CheckLayout(index uint32, bpfMaps map[bpf.BpfMapName]*ebpf.Map) (count uint32, err error) {
	var layoutError bpfLayoutError
	lookupErr := bpfMaps[LayoutErrorMap].Lookup(index, &layoutError)

	if err = lookupErr; err != nil {
		err = fmt.Errorf("lookup %s index %d: %w", bpfMapLayoutErrorMap, index, err)
		return
	}

	count, err = layoutMismatch(layoutError)
	return
}

// the error of the layout_error_map entry, nil while no call was rejected
func layoutMismatch(layoutError bpfLayoutError) (count uint32, err error) {
	count = layoutError.Count

	if count == 0 {
		return
	}

	err = fmt.Errorf("%w: %d secrets rejected, the last one %s with version 0x%04x and a %d byte secret", ErrLayoutMismatch, count, secretLabel(layoutError.SecretBit), layoutError.TlsVersion, layoutError.SecretLength)
	return
}

// SymbolHooks are the libssl functions whose return the secrets uprobe reads, SSL_connect and SSL_accept delegate to SSL_do_handshake, the _ex variants carry python's implicit handshake
func SymbolHooks() (symbols []string) {
	symbols = []string{"SSL_do_handshake", "SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"}
	return
}
