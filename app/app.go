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
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/proxy"
	"github.com/decerter/decerter/internal/route"
	"github.com/decerter/decerter/internal/tls/openssl"
	"github.com/cilium/ebpf"
)

const (
	routeSyncDebounce time.Duration = 100 * time.Millisecond
	routeSyncRetry    time.Duration = time.Second
	// datagrams of a closed UDP socket can still wait in the proxy socket, its flow is removed this long after the close
	udpReleaseDelay time.Duration = 2 * time.Second
	// how often released UDP flows are looked for, a flow lives at most udpReleaseDelay + udpReleaseSweep after the close
	udpReleaseSweep time.Duration = time.Second
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
	libssl              string
	logger              *slog.Logger
	redirectBpfMaps     map[bpf.BpfMapName]*ebpf.Map
	redirectBpfPrograms map[bpf.BpfProgramName]*ebpf.Program
	secretsBpfMaps      map[bpf.BpfMapName]*ebpf.Map
	secretsBpfPrograms  map[bpf.BpfProgramName]*ebpf.Program
	tcpListener         *net.TCPListener
	udpConnection       *net.UDPConn
	closeFunctions      [](func() error)
}

// keylog is the -keylog mode: load and attach only the secrets uprobe and print NSS key log lines, no redirect, proxy or route sync
// libssl overrides the resolved libssl path, empty means search the standard directories
func New(ctx context.Context, filter redirect.Filter, proxyPort uint16, udpIdleTimeout time.Duration, flowTable bool, keylog bool, libssl string, logger *slog.Logger) (app App) {
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
		libssl:              libssl,
		logger:              logger,
		redirectBpfMaps:     nil,
		redirectBpfPrograms: nil,
		secretsBpfMaps:      nil,
		secretsBpfPrograms:  nil,
		tcpListener:         nil,
		udpConnection:       nil,
		closeFunctions:      [](func() error){},
	}
	return
}

func (app *App) LoadBpfObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := redirect.LoadBpfObjects(app.proxyPort, uint32(os.Getpid()))

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
		app.logger.Warn("No uid or pid given, no flow will be redirected")
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

	// tcp proxy, closes the listener when the context is cancelled
	app.waitGroup.Go(func() {
		proxy.ServeTCP(app.ctx, app.tcpListener, app.redirectBpfMaps, app.waitGroup, app.logger)
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

func (app *App) AttachRedirect() (err error) {
	attachments := []struct {
		program    bpf.BpfProgramName
		attachType ebpf.AttachType
	}{
		// the programs that learn clients, restore addresses and clean up come first, so the first redirected socket already has them
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

	for _, attachment := range attachments {
		closeFunction, attachErr := attach.AddCgroup(attach.CgroupRoot, app.redirectBpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			app.logger.Error("Could not attach redirect program", "error", err, "attachType", attachment.attachType)
			return
		}

		app.closeFunctions = append(app.closeFunctions, closeFunction)
	}

	app.logger.Info("Redirecting flows", "cgroup", attach.CgroupRoot, "uids", app.filter.UIDs, "pids", app.filter.Tgids, "destinationCidrs", app.filter.DestinationCIDRs, "destinationPorts", app.filter.DestinationPorts, "proxyPort", app.proxyPort)
	return
}

// sock_release only marks a released redirected UDP flow, this removes it and its client_map entry udpReleaseDelay later
// started before AttachRedirect, so no released flow is missed
func (app *App) StartReleaseSweep() {
	// released udp flow remover
	app.waitGroup.Go(func() {
		app.watchReleasedFlows()
	})
}

// a failed sweep is retried with the next tick, the flows stay marked
func (app *App) watchReleasedFlows() {
	ticker := time.NewTicker(udpReleaseSweep)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			app.logger.Debug("Context cancelled")
			return
		case <-ticker.C:
			forgetErr := redirect.ForgetReleasedFlows(udpReleaseDelay, app.redirectBpfMaps)

			if forgetErr != nil {
				app.logger.Warn("Could not remove released udp flows", "error", forgetErr)
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
// in run mode the redirect object has to be loaded already, the secrets object shares its uid_map and tgid_map; in keylog mode it owns them
// on an architecture without the secrets object keylog mode fails, run mode goes on without TLS secrets
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

	// run mode shares the redirect object's selection maps so the same -uid and -pid select the flows and the secrets
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
