// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/proxy"
	"github.com/decerter/decerter/internal/route"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/cilium/ebpf"
)

const (
	routeSyncDebounce time.Duration = 100 * time.Millisecond
	routeSyncRetry    time.Duration = time.Second
	// datagrams of a closed UDP socket can still wait in the proxy socket, its flow is removed this long after the close
	// in capture mode every flow is removed this long after its socket closed: the RST of an aborted connection leaves after the close, and the capture writer can still read the flow of a packet it gets late
	releaseDelay time.Duration = 2 * time.Second
	// how often released flows are looked for, a flow lives at most releaseDelay + releaseSweep after the close
	releaseSweep time.Duration = time.Second
)

type App struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	waitGroup           *sync.WaitGroup
	filter              redirect.Filter
	proxyPort           uint16
	udpIdleTimeout      time.Duration
	flowTable           bool
	keylog              bool
	decrypt             bool
	libssl              string
	capturePath         string
	plaintext           bool
	snaplen             uint32
	logger              *slog.Logger
	redirectBpfMaps     map[bpf.BpfMapName]*ebpf.Map
	redirectBpfPrograms map[bpf.BpfProgramName]*ebpf.Program
	secretsBpfMaps      map[bpf.BpfMapName]*ebpf.Map
	secretsBpfPrograms  map[bpf.BpfProgramName]*ebpf.Program
	captureBpfMaps      map[bpf.BpfMapName]*ebpf.Map
	captureBpfPrograms  map[bpf.BpfProgramName]*ebpf.Program
	tcpListener         *net.TCPListener
	udpConnection       *net.UDPConn
	captureErr          error
	closeFunctions      [](func() error)
}

// keylog is the -keylog mode: load and attach only the secrets uprobe and print NSS key log lines, no redirect, proxy or route sync
// decrypt is the -decrypt option of run mode: the proxy decrypts the TLS flows with the secrets of the uprobe and prints their plaintext
// libssl overrides the resolved libssl path, empty means search the standard directories
// capturePath is the -capture mode: nothing is redirected, the packets of the selected flows and the secrets of their TLS sessions are written to this pcapng file, at most snaplen bytes of a packet
// plaintext is the -plaintext option of capture mode: the file gets synthesized packets with the decrypted payload instead of the captured packets and the secrets
func New(ctx context.Context, filter redirect.Filter, proxyPort uint16, udpIdleTimeout time.Duration, flowTable bool, keylog bool, decrypt bool, libssl string, capturePath string, plaintext bool, snaplen uint32, logger *slog.Logger) (app App) {
	appCtx, cancel := context.WithCancel(ctx)
	app = App{
		ctx:                 appCtx,
		cancel:              cancel,
		waitGroup:           &sync.WaitGroup{},
		filter:              filter,
		proxyPort:           proxyPort,
		udpIdleTimeout:      udpIdleTimeout,
		flowTable:           flowTable,
		keylog:              keylog,
		decrypt:             decrypt,
		libssl:              libssl,
		capturePath:         capturePath,
		plaintext:           plaintext,
		snaplen:             snaplen,
		logger:              logger,
		redirectBpfMaps:     nil,
		redirectBpfPrograms: nil,
		secretsBpfMaps:      nil,
		secretsBpfPrograms:  nil,
		captureBpfMaps:      nil,
		captureBpfPrograms:  nil,
		tcpListener:         nil,
		udpConnection:       nil,
		captureErr:          nil,
		closeFunctions:      [](func() error){},
	}
	return
}

// in capture mode the redirect object only records the flows
func (app *App) LoadBpfObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := redirect.LoadBpfObjects(app.proxyPort, uint32(os.Getpid()), app.capturePath != "")

	if err = loadErr; err != nil {
		app.logger.Error("Could not load redirect bpf objects", "error", err)
		return
	}

	app.redirectBpfMaps = bpfMaps
	app.redirectBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	return
}

func (app *App) UpdateBpfMaps() (err error) {
	err = redirect.UpdateBpfMaps(app.filter, app.redirectBpfMaps)

	if err != nil {
		app.logger.Error("Could not update redirect bpf maps", "error", err)
		return
	}

	// the destination filters only narrow the flows of the selected processes
	if (len(app.filter.UIDs) == 0) && (len(app.filter.Tgids) == 0) {
		app.logger.Warn("No uid or pid given, no flow will be redirected or captured")
	}

	return
}

// route_map has to be filled before AttachRedirect, connects to destinations without a route are not redirected
func (app *App) StartRouteSync() (err error) {
	subscription, subscribeErr := route.Subscribe()

	if err = subscribeErr; err != nil {
		app.logger.Error("Could not subscribe to route events", "error", err)
		return
	}

	err = app.syncRoutes()

	if err != nil {
		app.logger.Error("Could not sync routes", "error", err)
		err = errors.Join(err, subscription.Close())
		return
	}

	routeEvents := make(chan route.EventType, 5)

	// route event reader, closes the subscription when the context is cancelled
	app.waitGroup.Go(func() {
		route.Watch(app.ctx, subscription, routeEvents, app.logger)
	})

	// route_map sync
	app.waitGroup.Go(func() {
		app.watchRoutes(routeEvents)
	})

	return
}

// every event re-dumps all tables instead of applying single messages, the map value of a prefix depends on all tables and ecmp/replace messages
// the first event arms the debounce timer and later ones are merged into the same dump, so a burst (link up/down) costs one dump and a change waits at most routeSyncDebounce
func (app *App) watchRoutes(routeEvents <-chan route.EventType) {
	timer := time.NewTimer(routeSyncDebounce)
	timer.Stop()
	defer timer.Stop()
	pending := false

	for {
		select {
		case <-app.ctx.Done():
			app.logger.Debug("Context cancelled")
			return
		case event := <-routeEvents:
			switch event {
			case route.LostEventType:
				// lost events are not debounced, the map can already be wrong
				timer.Reset(0)
				pending = true
			case route.ChangedEventType:
				if !pending {
					timer.Reset(routeSyncDebounce)
					pending = true
				}
			default:
			}
		case <-timer.C:
			pending = false
			syncErr := app.syncRoutes()

			if syncErr != nil {
				// a failed sync keeps the previous routes until the retry
				app.logger.Warn("Could not sync routes, keeping the previous ones", "error", syncErr)
				timer.Reset(routeSyncRetry)
				pending = true
				continue
			}

			app.logger.Debug("Synced routes")
		}
	}
}

func (app *App) syncRoutes() (err error) {
	routes, listErr := route.List()

	if err = listErr; err != nil {
		return
	}

	err = redirect.UpdateRouteMap(routes, app.redirectBpfMaps)
	return
}

// the listener and the udp socket have to be up before AttachRedirect, otherwise redirected connects are refused and datagrams dropped
func (app *App) StartProxy() (err error) {
	listener, listenErr := proxy.ListenTCP(app.ctx, app.proxyPort)

	if err = listenErr; err != nil {
		app.logger.Error("Could not start tcp proxy", "error", err)
		return
	}

	app.tcpListener = listener
	app.logger.Info("Tcp proxy listening", "address", listener.Addr().String(), "device", "lo")

	// the proxy only looks into TLS flows when asked to, and it can't without the secrets object
	var secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map

	if app.decrypt && (app.secretsBpfMaps != nil) {
		secretsBpfMaps = app.secretsBpfMaps
		app.logger.Info("Decrypting tls flows of the tcp proxy")
	}

	// tcp proxy, closes the listener when the context is cancelled
	app.waitGroup.Go(func() {
		proxy.ServeTCP(app.ctx, app.tcpListener, app.redirectBpfMaps, secretsBpfMaps, app.waitGroup, app.logger)
	})

	connection, udpListenErr := proxy.ListenUDP(app.ctx, app.proxyPort)

	if err = udpListenErr; err != nil {
		app.logger.Error("Could not start udp proxy", "error", err)
		return
	}

	app.udpConnection = connection
	app.logger.Info("Udp proxy listening", "address", connection.LocalAddr().String(), "device", "lo", "idleTimeout", app.udpIdleTimeout)

	// udp proxy, closes the socket when the context is cancelled
	app.waitGroup.Go(func() {
		proxy.ServeUDP(app.ctx, app.udpConnection, app.udpIdleTimeout, app.redirectBpfMaps, app.waitGroup, app.logger)
	})

	return
}

// in capture mode nothing is redirected, so the programs that learn the udp client and restore the original address have nothing to do and stay detached
func (app *App) AttachRedirect() (err error) {
	type attachment struct {
		program    bpf.BpfProgramName
		attachType ebpf.AttachType
	}

	// the programs that learn clients, restore addresses and clean up come first, so the first redirected socket already has them
	attachments := []attachment{
		{program: redirect.ClientSockops, attachType: ebpf.AttachCGroupSockOps},
		{program: redirect.LearnUdpClient, attachType: ebpf.AttachCGroupInetEgress},
		{program: redirect.ForgetReleasedSocket, attachType: ebpf.AttachCgroupInetSockRelease},
		{program: redirect.RestoreGetpeername4, attachType: ebpf.AttachCgroupInet4GetPeername},
		{program: redirect.RestoreGetpeername6, attachType: ebpf.AttachCgroupInet6GetPeername},
		{program: redirect.RestoreRecvmsg4, attachType: ebpf.AttachCGroupUDP4Recvmsg},
		{program: redirect.RestoreRecvmsg6, attachType: ebpf.AttachCGroupUDP6Recvmsg},
		{program: redirect.RedirectConnect4, attachType: ebpf.AttachCGroupInet4Connect},
		{program: redirect.RedirectConnect6, attachType: ebpf.AttachCGroupInet6Connect},
		{program: redirect.RedirectSendmsg4, attachType: ebpf.AttachCGroupUDP4Sendmsg},
		{program: redirect.RedirectSendmsg6, attachType: ebpf.AttachCGroupUDP6Sendmsg},
	}

	if app.capturePath != "" {
		attachments = []attachment{
			{program: redirect.ClientSockops, attachType: ebpf.AttachCGroupSockOps},
			{program: redirect.ForgetReleasedSocket, attachType: ebpf.AttachCgroupInetSockRelease},
			{program: redirect.RedirectConnect4, attachType: ebpf.AttachCGroupInet4Connect},
			{program: redirect.RedirectConnect6, attachType: ebpf.AttachCGroupInet6Connect},
			{program: redirect.RedirectSendmsg4, attachType: ebpf.AttachCGroupUDP4Sendmsg},
			{program: redirect.RedirectSendmsg6, attachType: ebpf.AttachCGroupUDP6Sendmsg},
		}
	}

	for _, attachment := range attachments {
		closeFunction, attachErr := attach.AddCgroup(attach.CgroupRoot, app.redirectBpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			app.logger.Error("Could not attach redirect program", "error", err, "attachType", attachment.attachType)
			return
		}

		app.closeFunctions = append(app.closeFunctions, closeFunction)
	}

	if app.capturePath != "" {
		app.logger.Info("Recording flows", "cgroup", attach.CgroupRoot, "uids", app.filter.UIDs, "pids", app.filter.Tgids, "destinationCidrs", app.filter.DestinationCIDRs, "destinationPorts", app.filter.DestinationPorts)
		return
	}

	app.logger.Info("Redirecting flows", "cgroup", attach.CgroupRoot, "uids", app.filter.UIDs, "pids", app.filter.Tgids, "destinationCidrs", app.filter.DestinationCIDRs, "destinationPorts", app.filter.DestinationPorts, "proxyPort", app.proxyPort)
	return
}

// the redirect object has to be loaded already, the capture object shares its flow_map
func (app *App) LoadCaptureObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := capturebpf.LoadBpfObjects(app.snaplen, app.redirectBpfMaps[redirect.FlowMap], app.redirectBpfMaps[redirect.UidMap], app.redirectBpfMaps[redirect.TgidMap])

	if err = loadErr; err != nil {
		app.logger.Error("Could not load capture bpf objects", "error", err)
		return
	}

	app.captureBpfMaps = bpfMaps
	app.captureBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	return
}

// the capture file is created and the writer started before AttachCapture, so a path that can't be written fails before anything is attached and no packet waits in packet_map for a reader
func (app *App) StartCapture() (err error) {
	file, openErr := capture.OpenFile(app.capturePath)

	if err = openErr; err != nil {
		app.logger.Error("Could not open capture file", "error", err, "fileName", app.capturePath)
		return
	}

	switch {
	case (app.secretsBpfMaps == nil) && app.plaintext:
		app.logger.Warn("Capturing without TLS secrets, TLS flows will be written encrypted")
	case app.secretsBpfMaps == nil:
		app.logger.Warn("Capturing without TLS secrets, the file will have no keys")
	default:
	}

	// capture writer, writes the packets that wait and flushes the file when the context is cancelled
	app.waitGroup.Go(func() {
		writeErr := errors.Join(capture.Write(app.ctx, file, app.snaplen, app.plaintext, app.captureBpfMaps, app.secretsBpfMaps, app.logger), file.Close())

		if writeErr != nil {
			app.logger.Error("Could not write capture file", "error", writeErr, "fileName", app.capturePath)
			// read by Shutdown after the wait group, nothing is captured without the writer so decerter stops
			app.captureErr = writeErr
			app.cancel()
		}
	})

	return
}

// both programs see every packet of every socket and copy the ones of recorded sockets, they are attached before AttachRedirect records the first flow
func (app *App) AttachCapture() (err error) {
	attachments := []struct {
		program    bpf.BpfProgramName
		attachType ebpf.AttachType
	}{
		{program: capturebpf.CaptureIngress, attachType: ebpf.AttachCGroupInetIngress},
		{program: capturebpf.CaptureEgress, attachType: ebpf.AttachCGroupInetEgress},
	}

	for _, attachment := range attachments {
		closeFunction, attachErr := attach.AddCgroup(attach.CgroupRoot, app.captureBpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			app.logger.Error("Could not attach capture program", "error", err, "attachType", attachment.attachType)
			return
		}

		app.closeFunctions = append(app.closeFunctions, closeFunction)
	}

	app.logger.Info("Capturing packets", "cgroup", attach.CgroupRoot, "fileName", app.capturePath, "snaplen", app.snaplen, "plaintext", app.plaintext)
	return
}

// closed when decerter has to stop: the context of the caller was cancelled or the capture writer failed
func (app *App) Done() (done <-chan struct{}) {
	done = app.ctx.Done()
	return
}

// sock_release only marks a released redirected UDP flow, this removes it and its client_map entry releaseDelay later
// in capture mode sock_release and sockops mark every recorded flow, nothing is removed in the kernel
// started before AttachRedirect, so no released flow is missed
func (app *App) StartReleaseSweep() {
	// released flow remover
	app.waitGroup.Go(func() {
		app.watchReleasedFlows()
	})
}

// a failed sweep is retried with the next tick, the flows stay marked
func (app *App) watchReleasedFlows() {
	ticker := time.NewTicker(releaseSweep)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			app.logger.Debug("Context cancelled")
			return
		case <-ticker.C:
			forgetErr := redirect.ForgetReleasedFlows(releaseDelay, app.redirectBpfMaps)

			if forgetErr != nil {
				app.logger.Warn("Could not remove released flows", "error", forgetErr)
			}
		}
	}
}

// for debugging: the flow_map table, also shows the learned client endpoint of udp flows
func (app *App) StartFlowTable() {
	if !app.flowTable {
		return
	}

	// flow_map printer
	app.waitGroup.Go(func() {
		redirect.Read(app.ctx, app.redirectBpfMaps[redirect.FlowMap])
	})
}

// resolve libssl, detect the OpenSSL version and pick the offsets, then load the secrets object; an unknown version fails here, so this runs before anything is attached
// in run and capture mode the redirect object has to be loaded already, the secrets object shares its uid_map and tgid_map; in keylog mode it owns them
// on an architecture without the secrets object keylog mode fails, run and capture mode go on without TLS secrets
func (app *App) LoadSecretsBpfObjects() (err error) {
	err = secrets.CheckSupported()

	if err != nil {
		if app.keylog {
			app.logger.Error("Could not load secrets uprobe", "error", err)
			return
		}

		app.logger.Warn("Could not load secrets uprobe, running without TLS secrets", "error", err)
		err = nil
		return
	}

	libsslPath, libcryptoPath, findErr := openssl.FindLibssl(app.libssl)

	if err = findErr; err != nil {
		app.logger.Error("Could not find libssl", "error", err)
		return
	}

	version, versionErr := openssl.DetectVersion(libcryptoPath)

	if err = versionErr; err != nil {
		app.logger.Error("Could not detect OpenSSL version", "error", err, "libcrypto", libcryptoPath)
		return
	}

	offset, offsetErr := openssl.GetOffset(version)

	if err = offsetErr; err != nil {
		app.logger.Error("Could not get OpenSSL offsets", "error", err, "version", version)
		return
	}

	app.libssl = libsslPath

	var sharedUidMap, sharedTgidMap *ebpf.Map

	// run and capture mode share the redirect object's selection maps so the same -uid and -pid select the flows and the secrets
	if !app.keylog {
		sharedUidMap = app.redirectBpfMaps[redirect.UidMap]
		sharedTgidMap = app.redirectBpfMaps[redirect.TgidMap]
	}

	bpfMaps, bpfPrograms, closeFunction, loadErr := secrets.LoadBpfObjects(offset, uint32(os.Getpid()), sharedUidMap, sharedTgidMap)

	if err = loadErr; err != nil {
		app.logger.Error("Could not load secrets bpf objects", "error", err)
		return
	}

	app.secretsBpfMaps = bpfMaps
	app.secretsBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	app.logger.Info("Loaded secrets uprobe", "libssl", libsslPath, "version", version)
	return
}

// keylog mode fills the secrets object's own uid_map and tgid_map; run mode shares the redirect's maps, which are already filled, and skips this
func (app *App) UpdateSecretsSelection() (err error) {
	if !app.keylog {
		return
	}

	err = secrets.UpdateSelection(app.filter.UIDs, app.filter.Tgids, app.secretsBpfMaps)

	if err != nil {
		app.logger.Error("Could not update secrets selection maps", "error", err)
		return
	}

	// an empty selection reads nothing, warn like the redirect does
	if (len(app.filter.UIDs) == 0) && (len(app.filter.Tgids) == 0) {
		app.logger.Warn("No uid or pid given, no secret will be read")
	}

	return
}

// the key log reader is started before the uprobe is attached so no session is missed
func (app *App) StartKeylog() {
	if !app.keylog {
		return
	}

	// secrets key log printer, writes NSS key log lines to stdout
	app.waitGroup.Go(func() {
		secrets.ReadKeyLog(app.ctx, app.secretsBpfMaps[secrets.SecretsEventMap], os.Stdout, app.logger)
	})
}

// attach the entry and return uprobes to every libssl function that carries a complete handshake
// nothing to attach when run mode goes on without the secrets object
func (app *App) AttachSecrets() (err error) {
	if app.secretsBpfPrograms == nil {
		return
	}

	executable, openErr := attach.OpenExecutable(app.libssl)

	if err = openErr; err != nil {
		app.logger.Error("Could not open libssl", "error", err, "libssl", app.libssl)
		return
	}

	attachments := []struct {
		program  bpf.BpfProgramName
		isReturn bool
	}{
		{program: secrets.StashSsl, isReturn: false},
		{program: secrets.StoreSecrets, isReturn: true},
	}

	for _, symbol := range secrets.SymbolHooks() {
		for _, attachment := range attachments {
			closeFunction, attachErr := attach.AddUprobe(executable, symbol, app.secretsBpfPrograms[attachment.program], attachment.isReturn)

			if err = attachErr; err != nil {
				app.logger.Error("Could not attach secrets uprobe", "error", err, "symbol", symbol, "return", attachment.isReturn)
				return
			}

			app.closeFunctions = append(app.closeFunctions, closeFunction)
		}
	}

	app.logger.Info("Attached secrets uprobe", "libssl", app.libssl, "symbols", secrets.SymbolHooks(), "uids", app.filter.UIDs, "pids", app.filter.Tgids)
	return
}

// links are closed before the objects, in reverse order of creation
func (app *App) Shutdown() (err error) {
	app.cancel()
	app.waitGroup.Wait()
	err = app.captureErr

	for _, closeFunction := range slices.Backward(app.closeFunctions) {
		closeErr := closeFunction()

		if closeErr != nil {
			app.logger.Error("Could not close bpf resource", "error", closeErr)
		}

		err = errors.Join(err, closeErr)
	}

	app.closeFunctions = nil
	return
}
