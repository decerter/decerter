// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/decerter/decerter/api"
	"github.com/decerter/decerter/internal/api"
	"github.com/decerter/decerter/internal/attach"
	"github.com/decerter/decerter/internal/bpf"
	capturebpf "github.com/decerter/decerter/internal/bpf/capture"
	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/bpf/secrets"
	"github.com/decerter/decerter/internal/capture"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/history"
	"github.com/decerter/decerter/internal/intercept"
	"github.com/decerter/decerter/internal/output"
	"github.com/decerter/decerter/internal/platform"
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
	// how often the BoringSSL uprobe's layout errors are looked at, per library
	layoutCheck time.Duration = time.Second
	// in the platform's data directory, the lock held while decerter runs; the netd hooks decerter shared are in platform.NetdStateName next to it
	lockName string = "decerter.lock"
)

type cgroupAttachment struct {
	program    bpf.BpfProgramName
	attachType ebpf.AttachType
}

type App struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	waitGroup           *sync.WaitGroup
	filter              redirect.Filter
	scopeFilter         *filter.Filter
	selection           redirect.Filter
	scope               *filter.Filter
	proxyPort           uint16
	udpIdleTimeout      time.Duration
	blockQuic           bool
	flowTable           bool
	keylog              bool
	decrypt             bool
	rules               []intercept.Rule
	apiSocket           string
	holdTimeout         time.Duration
	assemblyTimeout     time.Duration
	apiServer           *api.Server
	backend             *api.Backend
	startTime           time.Time
	libssl              string
	boringsslHooks      []boringsslHook
	flutterSeen         map[string]bool
	opensslHooks        []opensslHook
	opensslSeen         map[string]bool
	isCapture           bool
	capturePath         string
	plaintext           bool
	snaplen             uint32
	platform            platform.Platform
	logger              *slog.Logger
	redirectBpfMaps     map[bpf.BpfMapName]*ebpf.Map
	redirectBpfPrograms map[bpf.BpfProgramName]*ebpf.Program
	secretsBpfMaps      map[bpf.BpfMapName]*ebpf.Map
	secretsBpfPrograms  map[bpf.BpfProgramName]*ebpf.Program
	captureBpfMaps      map[bpf.BpfMapName]*ebpf.Map
	captureBpfPrograms  map[bpf.BpfProgramName]*ebpf.Program
	tcpListener         *net.TCPListener
	udpConnection       *net.UDPConn
	stopErr             error
	stopErrMutex        *sync.Mutex
	secretsErr          error
	closeFunctions      [](func() error)
}

// keylog is the keylog command: load and attach only the secrets uprobe and print NSS key log lines, no redirect, proxy or route sync
// decrypt is the --decrypt option of run mode: the proxy decrypts the TLS flows with the secrets of the uprobe and prints their plaintext
// rules make the proxy intercept every flow instead of observing it: TLS records are decrypted, run through the rules, printed and sealed again, plain tcp and udp go through them too; empty intercepts nothing
// apiSocket serves the control API on this unix socket path, @name is an abstract socket, empty serves none; in run mode with rules the API adds its own rules and the hold queue after them, holdTimeout is how long a held message waits for a decision
// assemblyTimeout is how long a message kept back for the rules of layer http may take to come whole before it goes on as it came
// libssl overrides the resolved libssl path, empty means search the standard directories
// isCapture is the capture command: nothing is redirected, the packets of the selected flows and the secrets of their TLS sessions are written to the pcapng file at capturePath, empty writes none, and to the captures and streams of the API; at most snaplen bytes of a packet
// plaintext is the --plaintext option of capture mode: the file gets synthesized packets with the decrypted payload instead of the captured packets and the secrets
// currentPlatform decides where the netd hook state is kept and whether hooks held exclusively by another program may be shared, only on Android
// blockQuic is --block-quic of run and capture mode: UDP connects and sends of the selected processes to port 443 fail, so QUIC falls back to TLS over TCP
// flags is the kernel selection of --uid, --pid, --dst-cidr and --dst-port; scopeFilter the --filter, which narrows it: its kernel terms are added to the maps, the proxy and the capture writer decide the rest per flow; nil is no filter
func New(ctx context.Context, flags redirect.Filter, scopeFilter *filter.Filter, proxyPort uint16, udpIdleTimeout time.Duration, blockQuic bool, flowTable bool, keylog bool, decrypt bool, rules []intercept.Rule, apiSocket string, holdTimeout time.Duration, assemblyTimeout time.Duration, libssl string, isCapture bool, capturePath string, plaintext bool, snaplen uint32, currentPlatform platform.Platform, logger *slog.Logger) (app App) {
	appCtx, cancel := context.WithCancel(ctx)
	app = App{
		ctx:                 appCtx,
		cancel:              cancel,
		waitGroup:           &sync.WaitGroup{},
		filter:              flags,
		scopeFilter:         scopeFilter,
		selection:           redirect.Filter{},
		scope:               nil,
		proxyPort:           proxyPort,
		udpIdleTimeout:      udpIdleTimeout,
		blockQuic:           blockQuic,
		flowTable:           flowTable,
		keylog:              keylog,
		decrypt:             decrypt,
		rules:               rules,
		apiSocket:           apiSocket,
		holdTimeout:         holdTimeout,
		assemblyTimeout:     assemblyTimeout,
		apiServer:           nil,
		backend:             nil,
		startTime:           time.Now(),
		libssl:              libssl,
		boringsslHooks:      nil,
		flutterSeen:         nil,
		opensslHooks:        nil,
		opensslSeen:         nil,
		isCapture:           isCapture,
		capturePath:         capturePath,
		plaintext:           plaintext,
		snaplen:             snaplen,
		platform:            currentPlatform,
		logger:              logger,
		redirectBpfMaps:     nil,
		redirectBpfPrograms: nil,
		secretsBpfMaps:      nil,
		secretsBpfPrograms:  nil,
		captureBpfMaps:      nil,
		captureBpfPrograms:  nil,
		tcpListener:         nil,
		udpConnection:       nil,
		stopErr:             nil,
		stopErrMutex:        &sync.Mutex{},
		secretsErr:          nil,
		closeFunctions:      [](func() error){},
	}
	return
}

// in capture mode the redirect object only records the flows, with --block-quic it rejects QUIC of the selected processes in both modes
func (app *App) LoadBpfObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := redirect.LoadBpfObjects(app.proxyPort, uint32(os.Getpid()), app.isCapture, app.blockQuic)

	if err = loadErr; err != nil {
		app.logger.Error("Could not load redirect bpf objects", "error", err)
		return
	}

	app.redirectBpfMaps = bpfMaps
	app.redirectBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	return
}

// the kernel gets the flags and the kernel terms of the filter, Go keeps the filter when the kernel can't decide all of it
func (app *App) UpdateBpfMaps() (err error) {
	selection, scope, selectErr := app.kernelSelection()

	if err = selectErr; err != nil {
		app.logger.Error("Could not select flows", "error", err, "filter", app.scopeFilter.String())
		return
	}

	app.selection = selection
	app.scope = scope
	err = redirect.UpdateBpfMaps(app.selection, app.redirectBpfMaps)

	if err != nil {
		app.logger.Error("Could not update redirect bpf maps", "error", err)
		return
	}

	if app.scopeFilter != nil {
		app.logger.Info("Scope filter", "filter", app.scopeFilter.String(), "decidedInKernel", app.scope == nil, "uids", app.selection.UIDs, "pids", app.selection.Tgids, "comms", app.selection.Comms, "destinationCidrs", app.selection.DestinationCIDRs, "destinationPorts", app.selection.DestinationPorts)
	}

	// the destination filters only narrow the flows of the selected processes, a filter without a process was refused already
	if (app.scopeFilter == nil) && (len(app.selection.UIDs) == 0) && (len(app.selection.Tgids) == 0) {
		app.logger.Warn("No uid or pid given, no flow will be redirected or captured")
	}

	return
}

// without a filter the flags are the selection; with one, the kernel terms of its top-level && chain narrow the flags where a map can hold both, and scope is the filter when the kernel can't decide all of it
// a filter with no process in the flags or in its kernel terms is refused: it would select every process of the machine
func (app *App) kernelSelection() (selection redirect.Filter, scope *filter.Filter, err error) {
	if app.scopeFilter == nil {
		selection = app.filter
		return
	}

	flags := filter.Selection{
		HasProcess:       (len(app.filter.UIDs) > 0) || (len(app.filter.Tgids) > 0),
		UIDs:             app.filter.UIDs,
		Tgids:            app.filter.Tgids,
		HasComm:          len(app.filter.Comms) > 0,
		Comms:            app.filter.Comms,
		HasDestination:   len(app.filter.DestinationCIDRs) > 0,
		DestinationCIDRs: app.filter.DestinationCIDRs,
		HasPort:          len(app.filter.DestinationPorts) > 0,
		DestinationPorts: nil,
	}

	for _, destinationPort := range app.filter.DestinationPorts {
		flags.DestinationPorts = append(flags.DestinationPorts, filter.Port{Port: destinationPort.Port, IPProtocol: destinationPort.IPProtocol})
	}

	pushed, isPushExact := app.scopeFilter.Pushdown()
	merged, isMergeExact := filter.Intersect(flags, pushed)

	if !merged.HasProcess {
		err = ErrNoProcess
		return
	}

	if !isPushExact || !isMergeExact {
		scope = app.scopeFilter
	}

	// a part with nothing in it passes no flow, the maps can only say that with an empty process selection
	if merged.IsEmpty() {
		app.logger.Warn("The filter and the flags match no flow", "filter", app.scopeFilter.String())
		return
	}

	selection = redirect.Filter{
		UIDs:             merged.UIDs,
		Tgids:            merged.Tgids,
		DestinationCIDRs: merged.DestinationCIDRs,
		DestinationPorts: nil,
		Comms:            merged.Comms,
	}

	for _, destinationPort := range merged.DestinationPorts {
		selection.DestinationPorts = append(selection.DestinationPorts, redirect.DestinationPort{Port: destinationPort.Port, IPProtocol: destinationPort.IPProtocol})
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

	// the proxy only looks into TLS flows and DTLS sessions when asked to, and it can't without the secrets object
	var secretsBpfMaps map[bpf.BpfMapName]*ebpf.Map
	var pipeline *intercept.Pipeline
	isIntercepting := len(app.rules) > 0

	if (app.decrypt || isIntercepting) && (app.secretsBpfMaps != nil) {
		secretsBpfMaps = app.secretsBpfMaps
	}

	processing := v1.RelayProcessing

	switch {
	case isIntercepting:
		processing = v1.InterceptProcessing
	case secretsBpfMaps != nil:
		processing = v1.DecryptProcessing
	default:
	}

	// the API's history records every flow in scope, its rules and hold queue run after the rules of the code
	rules := app.rules
	var recorder *history.History

	if app.apiSocket != "" {
		app.backend = app.newBackend(v1.RunMode, processing)
		recorder = app.backend.History

		if isIntercepting {
			rules = append(slices.Clone(app.rules), app.backend.Rules, app.backend.Holds)
		}
	}

	switch processing {
	case v1.InterceptProcessing:
		var recordMessage intercept.Recorder

		if recorder != nil {
			recordMessage = recorder.Record
		}

		pipeline = intercept.New(rules, output.Stdout, recordMessage)
		app.logger.Info("Intercepting the flows of the proxy", "rules", len(app.rules), "tls", secretsBpfMaps != nil)
	case v1.DecryptProcessing:
		app.logger.Info("Decrypting tls flows of the tcp proxy and dtls sessions of the udp proxy")
	default:
	}

	// the API's history gets the HTTP/1 exchanges of the tcp flows; when the proxy intercepts, the API's rules and hold queue of layer http run on whole messages, after the record rules
	var httpLayer *proxy.HTTPLayer

	if recorder != nil {
		httpLayer = &proxy.HTTPLayer{Pipeline: nil, Timeout: app.assemblyTimeout}

		if pipeline != nil {
			httpLayer.Pipeline = pipeline.Derive([]intercept.Rule{app.backend.Rules, app.backend.Holds})
		}
	}

	// tcp proxy, closes the listener when the context is cancelled
	app.waitGroup.Go(func() {
		proxy.ServeTCP(app.ctx, app.tcpListener, app.redirectBpfMaps, secretsBpfMaps, app.captureBpfMaps, pipeline, httpLayer, app.scope, recorder, app.waitGroup, app.logger)
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
		proxy.ServeUDP(app.ctx, app.udpConnection, app.udpIdleTimeout, app.redirectBpfMaps, secretsBpfMaps, app.captureBpfMaps, pipeline, app.scope, recorder, app.waitGroup, app.logger)
	})

	return
}

// the control API socket is created first, a path that can't be used stops decerter before anything is attached; it is served last, by ServeAPI
func (app *App) ListenAPI() (err error) {
	if app.apiSocket == "" {
		return
	}

	server, listenErr := api.Listen(app.apiSocket, app.platform, app.logger)

	if err = listenErr; err != nil {
		return
	}

	app.apiServer = server
	app.closeFunctions = append(app.closeFunctions, server.Close)
	return
}

// what the API serves of this run: the history and, when the proxy intercepts, its rules and hold queue; the key log is read from secrets_map when it is asked for
// capture mode adds its captures to it
func (app *App) newBackend(mode v1.Mode, processing v1.Processing) (backend *api.Backend) {
	scope := ""

	if app.scopeFilter != nil {
		scope = app.scopeFilter.String()
	}

	info := api.Info{
		Mode:               mode,
		Processing:         processing,
		Platform:           string(app.platform.Type),
		Scope:              scope,
		Started:            app.startTime,
		HoldTimeout:        app.holdTimeout,
		HasTLSSecrets:      app.secretsBpfMaps != nil,
		IsInterceptCapable: processing == v1.InterceptProcessing,
	}
	var keyLog func(clientRandom [32]byte) (keyLog string, found bool, err error)

	if app.secretsBpfMaps != nil {
		secretsBpfMaps := app.secretsBpfMaps
		keyLog = func(clientRandom [32]byte) (keyLog string, found bool, err error) {
			keyLog, found, err = secrets.LookupKeyLog(clientRandom, secretsBpfMaps)
			return
		}
	}

	backend = api.NewBackend(info, history.DefaultLimits(), keyLog)
	return
}

// serve the control API until decerter stops, everything it serves is running by now
func (app *App) ServeAPI() {
	if app.apiServer == nil {
		return
	}

	// control api server, removes its socket when the context is cancelled
	app.waitGroup.Go(func() {
		app.apiServer.Serve(app.ctx, app.backend, app.logger)
	})
}

// the programs that learn clients, restore addresses and clean up come first, so the first redirected socket already has them
// in capture mode nothing is redirected, so the programs that learn the udp client and restore the original address have nothing to do and stay detached
func (app *App) redirectAttachments() (attachments []cgroupAttachment) {
	if app.isCapture {
		attachments = []cgroupAttachment{
			{program: redirect.ClientSockops, attachType: ebpf.AttachCGroupSockOps},
			{program: redirect.ForgetReleasedSocket, attachType: ebpf.AttachCgroupInetSockRelease},
			{program: redirect.RedirectConnect4, attachType: ebpf.AttachCGroupInet4Connect},
			{program: redirect.RedirectConnect6, attachType: ebpf.AttachCGroupInet6Connect},
			{program: redirect.RedirectSendmsg4, attachType: ebpf.AttachCGroupUDP4Sendmsg},
			{program: redirect.RedirectSendmsg6, attachType: ebpf.AttachCGroupUDP6Sendmsg},
		}
		return
	}

	attachments = []cgroupAttachment{
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
	return
}

// capture mode copies the packets of the recorded sockets, run mode with the API the ones of the proxy's upstream sockets
func (app *App) captureAttachments() (attachments []cgroupAttachment) {
	if !app.hasCapture() {
		return
	}

	attachments = []cgroupAttachment{
		{program: capturebpf.CaptureIngress, attachType: ebpf.AttachCGroupInetIngress},
		{program: capturebpf.CaptureEgress, attachType: ebpf.AttachCGroupInetEgress},
	}
	return
}

func (app *App) AttachRedirect() (err error) {
	for _, attachment := range app.redirectAttachments() {
		closeFunction, attachErr := attach.AddCgroup(attach.CgroupRoot, app.redirectBpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			app.logger.Error("Could not attach redirect program", "error", err, "attachType", attachment.attachType)
			return
		}

		app.closeFunctions = append(app.closeFunctions, closeFunction)
	}

	if app.isCapture {
		app.logger.Info("Recording flows", "cgroup", attach.CgroupRoot, "uids", app.selection.UIDs, "pids", app.selection.Tgids, "destinationCidrs", app.selection.DestinationCIDRs, "destinationPorts", app.selection.DestinationPorts, "comms", app.selection.Comms)
		return
	}

	app.logger.Info("Redirecting flows", "cgroup", attach.CgroupRoot, "uids", app.selection.UIDs, "pids", app.selection.Tgids, "destinationCidrs", app.selection.DestinationCIDRs, "destinationPorts", app.selection.DestinationPorts, "comms", app.selection.Comms, "proxyPort", app.proxyPort)
	return
}

// capture mode, and run mode with the API: its captures and its stream record what the proxy's upstream sockets send and get, the wire side after the rules
// the app's sockets of run mode only talk to the proxy over loopback, their packets are not captured: the history and the plaintext export have that side
func (app *App) hasCapture() (hasCapture bool) {
	hasCapture = app.isCapture || ((app.apiSocket != "") && !app.keylog)
	return
}

// the redirect object has to be loaded already, the capture object shares its flow_map
// in run mode the programs only copy the packets of the proxy's upstream sockets, the proxy writes them into upstream_map
func (app *App) LoadCaptureObjects() (err error) {
	bpfMaps, bpfPrograms, closeFunction, loadErr := capturebpf.LoadBpfObjects(app.snaplen, !app.isCapture, app.redirectBpfMaps[redirect.FlowMap], app.redirectBpfMaps[redirect.UidMap], app.redirectBpfMaps[redirect.TgidMap])

	if err = loadErr; err != nil {
		app.logger.Error("Could not load capture bpf objects", "error", err)
		return
	}

	app.captureBpfMaps = bpfMaps
	app.captureBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	return
}

// the capture file is created and the hub with its writers started before AttachCapture, so a path that can't be written fails before anything is attached and no packet waits in packet_map for a reader
// with the API the hub keeps a history of the flows and their latest packets, and the API starts captures and streams behind it
// in run mode StartProxy made the API's backend and the proxy keeps its history, the hub only keeps the packets; there is no file
func (app *App) StartCapture() (err error) {
	var file *os.File

	if app.capturePath != "" {
		opened, openErr := capture.OpenFile(app.capturePath)

		if err = openErr; err != nil {
			app.logger.Error("Could not open capture file", "error", err, "fileName", app.capturePath)
			return
		}

		file = opened
	}

	// the one warning about missing secrets in capture mode, with the reason from LoadSecretsBpfObjects; run mode warned already
	switch {
	case !app.isCapture:
	case (app.secretsBpfMaps == nil) && app.plaintext:
		app.logger.Warn("Capturing without TLS secrets, TLS flows will be written encrypted", "reason", app.secretsErr)
	case app.secretsBpfMaps == nil:
		app.logger.Warn("Capturing without TLS secrets, the captures will have no keys", "reason", app.secretsErr)
	default:
	}

	var recorder *history.History

	if (app.apiSocket != "") && app.isCapture {
		app.backend = app.newBackend(v1.CaptureMode, v1.RecordProcessing)
	}

	if app.backend != nil {
		recorder = app.backend.History
	}

	hub, hubErr := capture.NewHub(app.snaplen, app.captureBpfMaps, app.secretsBpfMaps, app.scope, recorder, !app.isCapture, app.logger)

	if err = hubErr; err != nil {
		app.logger.Error("Could not start capture", "error", err)
		err = errors.Join(err, closeCaptureFile(file))
		return
	}

	if app.apiSocket != "" {
		captures, capturesErr := capture.NewCaptures(hub, app.platform.DataDirectory, app.logger)

		if err = capturesErr; err != nil {
			app.logger.Error("Could not prepare captures", "error", err)
			err = errors.Join(err, closeCaptureFile(file))
			return
		}

		app.backend.Captures = captures
		app.closeFunctions = append(app.closeFunctions, captures.Close)
	}

	var fileConsumer *capture.Consumer
	stream := app.capturePath == capture.StreamPath

	if file != nil {
		consumer, addErr := hub.Add(file, capture.ConsumerOptions{Stream: stream, IsCut: false, Scope: nil, Plaintext: app.plaintext, Limit: nil}, app.logger)

		if err = addErr; err != nil {
			app.logger.Error("Could not write capture file", "error", err, "fileName", app.capturePath)
			err = errors.Join(err, closeCaptureFile(file))
			return
		}

		fileConsumer = consumer
	}

	// packet_map reader, hands the packets to the writers until the context is cancelled and closes Done after the last one
	app.waitGroup.Go(func() {
		runErr := hub.Run(app.ctx)

		if runErr != nil {
			app.logger.Error("Could not read captured packets", "error", runErr)
			app.setStopErr(runErr)
			app.cancel()
		}
	})

	if file == nil {
		return
	}

	// capture writer, writes the packets that wait and flushes the file when the hub is done
	app.waitGroup.Go(func() {
		writeErr := hub.Consume(context.Background(), fileConsumer, nil)

		// stdout stays open for the stream reader watcher until decerter exits
		if !stream {
			writeErr = errors.Join(writeErr, file.Close())
		}

		switch {
		case writeErr == nil:
		// tshark or Wireshark stopped reading, the capture ends with it; behind adb exec-out stdout is a pty, which fails with EIO when adb is gone
		case stream && (errors.Is(writeErr, syscall.EPIPE) || errors.Is(writeErr, syscall.EIO)):
			if app.ctx.Err() == nil {
				app.logger.Info("Capture stream reader went away, stopping")
			}

			app.cancel()
		default:
			app.logger.Error("Could not write capture file", "error", writeErr, "fileName", app.capturePath)
			// read by Shutdown after the wait group, nothing is captured without the writer so decerter stops
			app.setStopErr(writeErr)
			app.cancel()
		}
	})

	if !stream {
		return
	}

	// stream reader watcher, the writer only sees a closed pipe when it writes and a quiet capture writes nothing
	app.waitGroup.Go(func() {
		isGone, waitErr := capture.WaitReaderGone(app.ctx, file)

		if waitErr != nil {
			app.logger.Warn("Could not watch capture stream reader, decerter stops at the next write after it is gone", "error", waitErr)
			return
		}

		if isGone {
			app.logger.Info("Capture stream reader went away, stopping")
			app.cancel()
		}
	})

	return
}

// an error that stops decerter, from the capture writer or the key log reader, Shutdown returns it
func (app *App) setStopErr(err error) {
	app.stopErrMutex.Lock()
	defer app.stopErrMutex.Unlock()
	app.stopErr = errors.Join(app.stopErr, err)
}

// stdout is not closed, it is the stream
func closeCaptureFile(file *os.File) (err error) {
	if (file == nil) || (file == os.Stdout) {
		return
	}

	err = file.Close()
	return
}

// both programs see every packet of every socket and copy the ones of recorded sockets, they are attached before AttachRedirect records the first flow
func (app *App) AttachCapture() (err error) {
	if !app.hasCapture() {
		return
	}

	for _, attachment := range app.captureAttachments() {
		closeFunction, attachErr := attach.AddCgroup(attach.CgroupRoot, app.captureBpfPrograms[attachment.program], attachment.attachType)

		if err = attachErr; err != nil {
			app.logger.Error("Could not attach capture program", "error", err, "attachType", attachment.attachType)
			return
		}

		app.closeFunctions = append(app.closeFunctions, closeFunction)
	}

	if !app.isCapture {
		app.logger.Info("Capturing the packets of the proxy's upstream sockets for the api", "cgroup", attach.CgroupRoot, "snaplen", app.snaplen)
		return
	}

	app.logger.Info("Capturing packets", "cgroup", attach.CgroupRoot, "fileName", app.capturePath, "api", app.apiSocket != "", "snaplen", app.snaplen, "plaintext", app.plaintext)
	return
}

// closed when decerter has to stop: the context of the caller was cancelled or the capture writer failed
func (app *App) Done() (done <-chan struct{}) {
	done = app.ctx.Done()
	return
}

// sock_release only marks a released redirected UDP flow, this removes it and its client_map entry releaseDelay later
// in capture mode sock_release and sockops mark every recorded flow, nothing is removed in the kernel
// in run mode with the capture the proxy marks the upstream sockets it closed in upstream_map, they go the same way
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

			if app.isCapture || (app.captureBpfMaps == nil) {
				continue
			}

			forgetErr = capturebpf.ForgetReleasedUpstreams(releaseDelay, app.captureBpfMaps)

			if forgetErr != nil {
				app.logger.Warn("Could not remove released upstream sockets", "error", forgetErr)
			}
		}
	}
}

// for debugging: the flow_map table, also shows the learned client endpoint of udp flows
func (app *App) StartFlowTable() {
	if !app.flowTable {
		return
	}

	// stdout carries the capture stream, the table goes to stderr with the logs then
	var writer io.Writer = output.Stdout

	if app.capturePath == capture.StreamPath {
		writer = os.Stderr
	}

	// flow_map printer
	app.waitGroup.Go(func() {
		redirect.Read(app.ctx, app.redirectBpfMaps[redirect.FlowMap], writer)
	})
}

// resolve libssl and pick the offsets, then load the secrets object; an unknown OpenSSL version fails here, so this runs before anything is attached
// Linux hooks OpenSSL: the --libssl given, or every libssl.so.3 and libssl.so.4 of the linker cache plus the libssl the selected processes map (a
// container's own), each with the offsets of its version. Android hooks BoringSSL's ssl_log_secret in Conscrypt's libssl with the offsets of the Android release, and in the libflutter.so of
// each selected Flutter app with the offsets of its Dart version; with --libssl the library given, as BoringSSL when it has ssl_log_secret and as OpenSSL otherwise
// in run and capture mode the redirect object has to be loaded already, the secrets object shares its uid_map and tgid_map; in keylog mode it owns them
// on an architecture without the secrets object, on Linux without libssl.so.3 or .4 (and no --libssl), and on Android when neither Conscrypt nor a Flutter
// app can be hooked, keylog mode fails, run and capture mode go on without TLS secrets
func (app *App) LoadSecretsBpfObjects() (err error) {
	supportedErr := secrets.CheckSupported()

	if supportedErr != nil {
		err = app.withoutSecrets(supportedErr)
		return
	}

	var (
		libsslPaths  []string
		libraries    []string
		opensslHooks []opensslHook
		opensslSeen  map[string]bool
	)

	hooks, useBoringssl, seen, boringsslErr := app.findBoringsslHooks()

	if boringsslErr != nil {
		err = app.withoutSecrets(boringsslErr)
		return
	}

	if useBoringssl {
		for _, hook := range hooks {
			libsslPaths = append(libsslPaths, hook.Path)
			libraries = append(libraries, hook.Library)
		}
	} else {
		found, foundSeen, findErr := app.findOpensslHooks()

		// no libssl.so.3 or .4 on the host and none mapped by a selected process: run and capture mode go on without TLS secrets, keylog mode fails;
		// a --libssl that is not there always fails
		if (app.libssl == "") && errors.Is(findErr, openssl.ErrLibraryNotFound) {
			err = app.withoutSecrets(findErr)
			return
		}

		if err = findErr; err != nil {
			return
		}

		for _, hook := range found {
			libsslPaths = append(libsslPaths, hook.Library.Libssl)
			libraries = append(libraries, "OpenSSL "+hook.Library.Version)
		}

		opensslHooks = found
		opensslSeen = foundSeen
	}

	var sharedUidMap, sharedTgidMap *ebpf.Map

	// run and capture mode share the redirect object's selection maps so the same --uid and --pid select the flows and the secrets
	if !app.keylog {
		sharedUidMap = app.redirectBpfMaps[redirect.UidMap]
		sharedTgidMap = app.redirectBpfMaps[redirect.TgidMap]
	}

	bpfMaps, bpfPrograms, closeFunction, loadErr := secrets.LoadBpfObjects(uint32(os.Getpid()), sharedUidMap, sharedTgidMap)

	if err = loadErr; err != nil {
		app.logger.Error("Could not load secrets bpf objects", "error", err)
		return
	}

	app.boringsslHooks = hooks
	app.flutterSeen = seen
	app.opensslHooks = opensslHooks
	app.opensslSeen = opensslSeen
	app.secretsBpfMaps = bpfMaps
	app.secretsBpfPrograms = bpfPrograms
	app.closeFunctions = append(app.closeFunctions, closeFunction)
	app.logger.Info("Loaded secrets uprobe", "libssl", strings.Join(libsslPaths, ", "), "library", strings.Join(libraries, ", "))
	return
}

// keylog mode can't run without secrets; run mode warns once here, capture mode once in StartCapture, where it says what the file is missing
func (app *App) withoutSecrets(reason error) (err error) {
	if app.keylog {
		err = reason
		app.logger.Error("Could not load secrets uprobe", "error", err)
		return
	}

	app.secretsErr = reason

	if !app.isCapture {
		app.logger.Warn("Could not load secrets uprobe, running without TLS secrets", "error", reason)
	}

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

	// secrets key log printer, writes NSS key log lines to stdout; keylog mode has nothing else to do, a reader that gave up stops decerter
	app.waitGroup.Go(func() {
		readErr := secrets.ReadKeyLog(app.ctx, app.secretsBpfMaps[secrets.SecretsEventMap], output.Stdout, app.logger)

		switch {
		case readErr == nil:
		// the reader of stdout went away, output.Stdout stopped decerter already
		case output.IsGone(readErr):
		default:
			app.setStopErr(readErr)
			app.cancel()
		}
	})
}

// OpenSSL: attach the entry and return uprobes to every libssl function that carries a complete handshake, in each libssl found, and watch for libssl
// files selected processes start to map
// BoringSSL: attach one entry uprobe to ssl_log_secret of each library, by file offset because the symbol is not exported, and watch for layout errors and new Flutter apps
// nothing to attach when run mode goes on without the secrets object
func (app *App) AttachSecrets() (err error) {
	if app.secretsBpfPrograms == nil {
		return
	}

	if app.boringsslHooks != nil {
		err = app.attachBoringsslHooks()
		return
	}

	err = app.attachOpensslHooks()
	return
}

// one close function for links that don't depend on each other and whose close waits in the kernel: they are closed at the same time and the errors joined
func closeTogether(closeFunctions [](func() error)) (closeFunction func() error) {
	closeFunction = func() (err error) {
		var waitGroup sync.WaitGroup
		closeErrs := make([]error, len(closeFunctions))

		// link closers
		for index, linkClose := range closeFunctions {
			waitGroup.Go(func() {
				closeErrs[index] = linkClose()
			})
		}

		waitGroup.Wait()
		err = errors.Join(closeErrs...)
		return
	}
	return
}

// keylog mode selects with the flags, run and capture mode share the redirect's maps
func (app *App) secretsUIDs() (uids []uint32) {
	uids = app.selection.UIDs

	if app.keylog {
		uids = app.filter.UIDs
	}

	return
}

func (app *App) secretsTgids() (tgids []uint32) {
	tgids = app.selection.Tgids

	if app.keylog {
		tgids = app.filter.Tgids
	}

	return
}

// on Android: create the data directory, take the lock and, when a decerter before was killed while it shared netd's hooks, put them back before anything else
// the lock is released last in Shutdown, after the hooks are back
// SIGPIPE is ignored there, a closed adb session must not kill decerter before it restored the hooks; logs to a closed stderr are lost then
func (app *App) PreparePlatform() (err error) {
	if app.platform.Type != platform.AndroidType {
		return
	}

	app.logger.Debug("Running on Android", "sdk", app.platform.SDK, "release", app.platform.Release, "dataDirectory", app.platform.DataDirectory)
	signal.Ignore(syscall.SIGPIPE)
	err = app.lockDataDirectory()

	if err != nil {
		return
	}

	err = app.restoreNetdState(true)
	return
}

func (app *App) lockDataDirectory() (err error) {
	err = platform.CreateDataDirectory(app.platform.DataDirectory)

	if err != nil {
		app.logger.Error("Could not create data directory", "error", err)
		return
	}

	unlock, lockErr := attach.LockNetdState(filepath.Join(app.platform.DataDirectory, lockName))

	if err = lockErr; err != nil {
		app.logger.Error("Could not lock data directory", "error", err)
		return
	}

	app.closeFunctions = append(app.closeFunctions, unlock)
	return
}

// the decerter android restore entry point: put netd's hooks back from the state a killed decerter left, refused while another decerter runs
func (app *App) RestoreNetdHooks() (err error) {
	if app.platform.Type != platform.AndroidType {
		app.logger.Info("Not on Android, nothing to restore")
		return
	}

	err = app.lockDataDirectory()

	if err != nil {
		return
	}

	err = app.restoreNetdState(false)
	return
}

// isStale is the check at start, a state file then means the decerter before did not exit cleanly
// the state file is removed only when every hook is back
func (app *App) restoreNetdState(isStale bool) (err error) {
	statePath := filepath.Join(app.platform.DataDirectory, platform.NetdStateName)
	state, readErr := attach.ReadNetdState(statePath)

	if errors.Is(readErr, fs.ErrNotExist) {
		if !isStale {
			app.logger.Info("No netd hook state, nothing to restore", "fileName", statePath)
		}

		return
	}

	if err = readErr; err != nil {
		app.logger.Error("Could not read netd hook state", "error", err, "fileName", statePath)
		return
	}

	if isStale {
		app.logger.Warn("Found the netd hook state of a decerter that did not exit cleanly, restoring netd's hooks first", "fileName", statePath, "pid", state.Pid)
	}

	restored, restoreErr := attach.RestoreHooks(state.Cgroup, state.Hooks)
	app.logRestoredHooks(restored)

	if err = restoreErr; err != nil {
		app.logger.Error("Could not restore netd hooks, the state file is kept for decerter android restore", "error", err, "fileName", statePath)
		return
	}

	err = attach.RemoveNetdState(statePath)

	if err != nil {
		app.logger.Error("Could not remove netd hook state", "error", err, "fileName", statePath)
		return
	}

	app.logger.Info("Netd hooks are exclusive again", "hooks", len(state.Hooks), "restored", len(restored))
	return
}

func (app *App) logRestoredHooks(restored []attach.SharedHook) {
	for _, hook := range restored {
		app.logger.Info("Restored netd cgroup hook", "attachType", hook.AttachTypeName, "program", hook.ProgramName, "programId", hook.ProgramID, "flags", hook.Flags, "gap", hook.Gap)
	}
}

// a hook held by one program without BPF_F_ALLOW_MULTI refuses decerter's links: on Android that is netd, its program is attached again in multi mode before decerter's links and put back by Shutdown after them
// on Linux the owner is unknown, so decerter refuses to start instead of changing it; usually nothing is held and this does nothing
// called right before the first cgroup link is attached
func (app *App) ShareNetdHooks() (err error) {
	attachTypes := []ebpf.AttachType{}

	for _, attachment := range slices.Concat(app.captureAttachments(), app.redirectAttachments()) {
		attachTypes = append(attachTypes, attachment.attachType)
	}

	hooks, queryErr := attach.ExclusiveHooks(attach.CgroupRoot, attachTypes)

	if err = queryErr; err != nil {
		app.logger.Error("Could not query cgroup hooks", "error", err)
		return
	}

	if len(hooks) == 0 {
		app.logger.Debug("No exclusive cgroup hooks")
		return
	}

	if app.platform.Type != platform.AndroidType {
		held := []string{}

		for _, hook := range hooks {
			held = append(held, fmt.Sprintf("%s by program %d %s", hook.AttachTypeName, hook.ProgramID, hook.ProgramName))
		}

		err = fmt.Errorf("%w: %s", attach.ErrExclusiveHook, strings.Join(held, ", "))
		app.logger.Error("Could not attach to cgroup", "error", err, "cgroup", attach.CgroupRoot)
		return
	}

	statePath := filepath.Join(app.platform.DataDirectory, platform.NetdStateName)
	shared, shareErr := attach.ShareHooks(attach.CgroupRoot, hooks, statePath)

	if err = shareErr; err != nil {
		app.logger.Error("Could not share netd hooks", "error", err, "fileName", statePath)
		return
	}

	for _, hook := range shared {
		app.logger.Info("Shared netd cgroup hook", "attachType", hook.AttachTypeName, "program", hook.ProgramName, "programId", hook.ProgramID, "pin", hook.PinPath, "gap", hook.Gap)
	}

	// runs after every cgroup link is closed, they are appended later
	app.closeFunctions = append(app.closeFunctions, func() (closeErr error) {
		restored, restoreErr := attach.RestoreHooks(attach.CgroupRoot, shared)
		app.logRestoredHooks(restored)

		if closeErr = restoreErr; closeErr != nil {
			app.logger.Error("Could not restore netd hooks, the state file is kept for decerter android restore", "error", closeErr, "fileName", statePath)
			return
		}

		closeErr = attach.RemoveNetdState(statePath)
		return
	})

	return
}

// the one start order of every mode, used by the run, capture and keylog commands and by the e2e tests
// the mode comes from New: keylog, isCapture, or run mode otherwise; Shutdown undoes whatever part of it ran, also after an error
func (app *App) Start() (err error) {
	// a write to stdout after its reader went away stops decerter, as other Unix tools do: decerter run | head stops once head exited
	output.Stdout.OnGone(func() {
		if app.ctx.Err() == nil {
			app.logger.Info("Stdout reader went away, stopping")
		}

		app.cancel()
	})
	// on Android a decerter killed before puts netd's hooks back first
	err = app.PreparePlatform()

	if err != nil {
		return
	}

	switch {
	case app.keylog:
		err = app.startKeylogMode()
	case app.isCapture:
		err = app.startCaptureMode()
	default:
		err = app.startRunMode()
	}

	return
}

// keylog mode loads and attaches only the libssl secrets uprobe and prints key log lines
func (app *App) startKeylogMode() (err error) {
	err = app.LoadSecretsBpfObjects()

	if err != nil {
		return
	}

	err = app.UpdateSecretsSelection()

	if err != nil {
		return
	}

	app.StartKeylog()
	err = app.AttachSecrets()
	return
}

// capture mode records the flows and copies their packets, no proxy listener and no route sync
func (app *App) startCaptureMode() (err error) {
	err = app.ListenAPI()

	if err != nil {
		return
	}

	err = app.LoadBpfObjects()

	if err != nil {
		return
	}

	err = app.UpdateBpfMaps()

	if err != nil {
		return
	}

	// an unknown OpenSSL version has to fail here, before anything is attached
	err = app.LoadSecretsBpfObjects()

	if err != nil {
		return
	}

	err = app.LoadCaptureObjects()

	if err != nil {
		return
	}

	err = app.StartCapture()

	if err != nil {
		return
	}

	// the uprobe and the packet programs are attached first, so the first recorded flow already has them
	err = app.AttachSecrets()

	if err != nil {
		return
	}

	err = app.ShareNetdHooks()

	if err != nil {
		return
	}

	err = app.AttachCapture()

	if err != nil {
		return
	}

	app.StartReleaseSweep()
	err = app.AttachRedirect()

	if err != nil {
		return
	}

	app.StartFlowTable()
	app.ServeAPI()
	return
}

func (app *App) startRunMode() (err error) {
	err = app.ListenAPI()

	if err != nil {
		return
	}

	err = app.LoadBpfObjects()

	if err != nil {
		return
	}

	err = app.UpdateBpfMaps()

	if err != nil {
		return
	}

	// an unknown OpenSSL version has to fail here, before the route sync, the proxy and every attach
	err = app.LoadSecretsBpfObjects()

	if err != nil {
		return
	}

	// with the API the proxy writes its upstream sockets into upstream_map of the capture object from its first connection on
	if app.hasCapture() {
		err = app.LoadCaptureObjects()

		if err != nil {
			return
		}
	}

	err = app.StartRouteSync()

	if err != nil {
		return
	}

	err = app.StartProxy()

	if err != nil {
		return
	}

	// the hub reads the packets of the upstream sockets for the captures and the stream of the API, which StartProxy made
	if app.hasCapture() {
		err = app.StartCapture()

		if err != nil {
			return
		}
	}

	// the uprobe is attached first, so the first redirected connection already leaves its secrets in secrets_map
	err = app.AttachSecrets()

	if err != nil {
		return
	}

	err = app.ShareNetdHooks()

	if err != nil {
		return
	}

	// the packet programs copy nothing until the proxy dials its first upstream socket
	err = app.AttachCapture()

	if err != nil {
		return
	}

	app.StartReleaseSweep()
	err = app.AttachRedirect()

	if err != nil {
		return
	}

	app.StartFlowTable()
	app.ServeAPI()
	return
}

// links are closed before the objects, in reverse order of creation
func (app *App) Shutdown() (err error) {
	app.cancel()
	app.waitGroup.Wait()
	app.stopErrMutex.Lock()
	err = app.stopErr
	app.stopErrMutex.Unlock()

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
