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
	"github.com/decerter/decerter/internal/proxy"
	"github.com/decerter/decerter/internal/route"
	"github.com/cilium/ebpf"
)

const (
	routeSyncDebounce time.Duration = 100 * time.Millisecond
	routeSyncRetry    time.Duration = time.Second
	// datagrams of a closed UDP socket can still wait in the proxy socket, its flow is removed this long after the close
	udpReleaseDelay time.Duration = 2 * time.Second
)

type App struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	waitGroup           *sync.WaitGroup
	filter              redirect.Filter
	proxyPort           uint16
	udpIdleTimeout      time.Duration
	flowTable           bool
	logger              *slog.Logger
	redirectBpfMaps     map[bpf.BpfMapName]*ebpf.Map
	redirectBpfPrograms map[bpf.BpfProgramName]*ebpf.Program
	tcpListener         *net.TCPListener
	udpConnection       *net.UDPConn
	closeFunctions      [](func() error)
}

func New(ctx context.Context, filter redirect.Filter, proxyPort uint16, udpIdleTimeout time.Duration, flowTable bool, logger *slog.Logger) (app App) {
	appCtx, cancel := context.WithCancel(ctx)
	app = App{
		ctx:                 appCtx,
		cancel:              cancel,
		waitGroup:           &sync.WaitGroup{},
		filter:              filter,
		proxyPort:           proxyPort,
		udpIdleTimeout:      udpIdleTimeout,
		flowTable:           flowTable,
		logger:              logger,
		redirectBpfMaps:     nil,
		redirectBpfPrograms: nil,
		tcpListener:         nil,
		udpConnection:       nil,
		closeFunctions:      [](func() error){},
	}
	return
}

func (app *App) LoadBpfObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := redirect.LoadBpfObjects(app.proxyPort, uint32(os.Getpid()), udpReleaseDelay)

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
