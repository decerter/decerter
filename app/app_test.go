// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/bpf/redirect"
	"github.com/decerter/decerter/internal/filter"
	"github.com/decerter/decerter/internal/platform"
	"github.com/decerter/decerter/internal/tls/openssl"
)

// Test if app.kernelSelection returns with the expected output: the flags narrowed by the kernel terms of the filter, and the filter as scope when the kernel can't decide all of it.
func TestKernelSelectionPositive(state *testing.T) {
	flags := redirect.Filter{
		UIDs:             []uint32{1001},
		DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		DestinationPorts: []redirect.DestinationPort{{Port: 443, IPProtocol: syscall.IPPROTO_TCP}, {Port: 8443, IPProtocol: syscall.IPPROTO_TCP}},
	}
	positiveCases := []struct {
		Name     string
		Flags    redirect.Filter
		Filter   string
		Expected redirect.Filter
		HasScope bool
	}{
		{Name: "no filter", Flags: flags, Filter: "", Expected: flags, HasScope: false},
		{Name: "a process in the filter alone", Flags: redirect.Filter{}, Filter: `proc.uid in {1001 1002} && tcp.dstport == 443`, Expected: redirect.Filter{UIDs: []uint32{1001, 1002}, DestinationPorts: []redirect.DestinationPort{{Port: 443, IPProtocol: syscall.IPPROTO_TCP}}}, HasScope: false},
		{Name: "narrowed flags", Flags: flags, Filter: `proc.comm == "curl" && tcp.dstport == 443 && ip.dst == 127.0.0.1`, Expected: redirect.Filter{UIDs: []uint32{1001}, DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, DestinationPorts: []redirect.DestinationPort{{Port: 443, IPProtocol: syscall.IPPROTO_TCP}}, Comms: []string{"curl"}}, HasScope: false},
		// a ClientHello field is decided per flow
		{Name: "tls field", Flags: flags, Filter: `tls.sni == "example.com"`, Expected: flags, HasScope: true},
	}

	for _, positive := range positiveCases {
		app, err := newTestApp(state.Context(), positive.Flags, positive.Filter, &bytes.Buffer{})

		if err != nil {
			state.Fatalf("Test of app.kernelSelection failed, case %q, cannot parse filter, error: %s", positive.Name, err.Error())
		}

		selection, scope, err := app.kernelSelection()

		if (err != nil) || !equalSelection(selection, positive.Expected) || ((scope != nil) != positive.HasScope) {
			state.Errorf("Test of app.kernelSelection function failed, case %q, selection should be %+v scope %v, selection: %+v scope %v, error: %v", positive.Name, positive.Expected, positive.HasScope, selection, scope != nil, err)
			return
		}
	}

	// flags and a filter that leave nothing select nothing, with a warning
	logs := &bytes.Buffer{}
	app, err := newTestApp(state.Context(), flags, `proc.uid == 1002`, logs)

	if err != nil {
		state.Fatalf("Test of app.kernelSelection failed, cannot parse filter, error: %s", err.Error())
	}

	selection, _, err := app.kernelSelection()

	if (err != nil) || !reflect.DeepEqual(selection, redirect.Filter{}) || !strings.Contains(logs.String(), "The filter and the flags match no flow") {
		state.Errorf("Test of app.kernelSelection function failed, selection should be empty with a warning, selection: %+v, error: %v, logs: %q", selection, err, logs.String())
		return
	}
}

// Test if app.kernelSelection returns with the expected errors: a filter that selects no process is refused.
func TestKernelSelectionNegative(state *testing.T) {
	negativeCases := []struct {
		Flags  redirect.Filter
		Filter string
	}{
		{Flags: redirect.Filter{}, Filter: `tcp.dstport == 443`},
		// a uid under || or ! is no selection the kernel can use
		{Flags: redirect.Filter{}, Filter: `proc.uid == 1001 || tcp.dstport == 443`},
		{Flags: redirect.Filter{}, Filter: `!(proc.uid == 0)`},
		{Flags: redirect.Filter{DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, Filter: `proc.comm == "curl"`},
	}

	for _, negative := range negativeCases {
		app, err := newTestApp(state.Context(), negative.Flags, negative.Filter, &bytes.Buffer{})

		if err != nil {
			state.Fatalf("Test of app.kernelSelection failed, cannot parse filter, error: %s", err.Error())
		}

		_, _, err = app.kernelSelection()

		if !errors.Is(err, ErrNoProcess) {
			state.Errorf("Test of app.kernelSelection function failed, filter %q, error should be %v, error: %v", negative.Filter, ErrNoProcess, err)
			return
		}
	}
}

// Test if app.secretsUIDs and app.secretsTgids return with the expected output: keylog mode selects with the flags, the other modes with the kernel selection.
func TestSecretsSelectionPositive(state *testing.T) {
	app, err := newTestApp(state.Context(), redirect.Filter{UIDs: []uint32{1001}, Tgids: []uint32{42}}, "", &bytes.Buffer{})

	if err != nil {
		state.Fatalf("Test of app.secretsUIDs failed, error: %s", err.Error())
	}

	app.selection = redirect.Filter{UIDs: []uint32{1002}, Tgids: []uint32{43}}

	if !reflect.DeepEqual(app.secretsUIDs(), []uint32{1002}) || !reflect.DeepEqual(app.secretsTgids(), []uint32{43}) {
		state.Errorf("Test of app.secretsUIDs function failed, run mode should use the selection: %v %v", app.secretsUIDs(), app.secretsTgids())
		return
	}

	app.keylog = true

	if !reflect.DeepEqual(app.secretsUIDs(), []uint32{1001}) || !reflect.DeepEqual(app.secretsTgids(), []uint32{42}) {
		state.Errorf("Test of app.secretsUIDs function failed, keylog mode should use the flags: %v %v", app.secretsUIDs(), app.secretsTgids())
		return
	}
}

// Test if app.closeTogether returns with the expected output: every close runs at the same time and their errors are joined.
func TestCloseTogetherPositive(state *testing.T) {
	const count = 4
	started := sync.WaitGroup{}
	started.Add(count)
	allStarted := make(chan struct{})
	closeErrs := []error{errors.New("first"), nil, errors.New("third"), nil}
	closeFunctions := [](func() error){}

	// close helper
	go func() {
		started.Wait()
		close(allStarted)
	}()

	for index := range count {
		closeFunctions = append(closeFunctions, func() (err error) {
			started.Done()

			// one after another this would wait forever, together they all go on
			select {
			case <-allStarted:
			case <-time.After(10 * time.Second):
				err = errors.New("closed one after another")
				return
			}

			err = closeErrs[index]
			return
		})
	}

	err := closeTogether(closeFunctions)()

	if !errors.Is(err, closeErrs[0]) || !errors.Is(err, closeErrs[2]) || strings.Contains(err.Error(), "one after another") {
		state.Errorf("Test of app.closeTogether function failed, error should join first and third, error: %v", err)
		return
	}

	if err = closeTogether(nil)(); err != nil {
		state.Errorf("Test of app.closeTogether function failed, nothing to close should be no error, error: %s", err.Error())
		return
	}
}

// Test if app.checkUnknownOpenssl returns with the expected output: an OpenSSL of the linker cache without offsets is a warning naming the nearest
// known version and the make command while another library is hooked, and nothing to warn about is no warning.
func TestCheckUnknownOpensslPositive(state *testing.T) {
	logs := &bytes.Buffer{}
	app, err := newTestApp(state.Context(), redirect.Filter{UIDs: []uint32{1001}}, "", logs)

	if err != nil {
		state.Fatalf("Test of app.checkUnknownOpenssl failed, error: %s", err.Error())
	}

	known := openssl.Library{Libssl: "/usr/lib64/libssl.so.3", Libcrypto: "/usr/lib64/libcrypto.so.3", Version: "3.5.9", Offset: openssl.Offset{}}
	unknown := unknownOpenssl{Library: openssl.Library{Libssl: "/usr/lib64/libssl.so.4", Libcrypto: "/usr/lib64/libcrypto.so.4", Version: "4.9.0", Offset: openssl.Offset{}}, Err: nil}
	_, unknown.Err = openssl.GetOffset(unknown.Library.Version, runtime.GOARCH)
	positiveCases := []struct {
		Name     string
		Hooks    []opensslHook
		Unknown  []unknownOpenssl
		Expected []string
	}{
		{Name: "a known library of the linker cache", Hooks: []opensslHook{{Library: known, Pid: 0, Process: ""}}, Unknown: []unknownOpenssl{unknown}, Expected: []string{"level=WARN", "libssl.so.4", "4.9.0", "the nearest known version is ", "make generate-openssl-offsets"}},
		{Name: "a library a selected process maps", Hooks: []opensslHook{{Library: known, Pid: 42, Process: "curl"}}, Unknown: []unknownOpenssl{unknown}, Expected: []string{"level=WARN", "libssl.so.4"}},
		{Name: "every library known", Hooks: []opensslHook{{Library: known, Pid: 0, Process: ""}}, Unknown: nil, Expected: nil},
	}

	for _, positive := range positiveCases {
		logs.Reset()
		err = app.checkUnknownOpenssl(positive.Hooks, positive.Unknown)

		if (err != nil) || (unknown.Err == nil) || ((positive.Expected == nil) && (logs.Len() != 0)) || !containsAll(logs.String(), positive.Expected) || strings.Contains(logs.String(), "level=ERROR") {
			state.Errorf("Test of app.checkUnknownOpenssl function failed, case %q, should warn with %q and go on, logs: %q, error: %v", positive.Name, positive.Expected, logs.String(), err)
			return
		}
	}
}

// Test if app.checkUnknownOpenssl returns with the expected errors: without any library decerter can hook, the unknown version fails.
func TestCheckUnknownOpensslNegative(state *testing.T) {
	logs := &bytes.Buffer{}
	app, err := newTestApp(state.Context(), redirect.Filter{UIDs: []uint32{1001}}, "", logs)

	if err != nil {
		state.Fatalf("Test of app.checkUnknownOpenssl failed, error: %s", err.Error())
	}

	_, unknownErr := openssl.GetOffset("9.0.0", runtime.GOARCH)
	unknown := []unknownOpenssl{{Library: openssl.Library{Libssl: "/usr/lib/libssl.so.9", Libcrypto: "/usr/lib/libcrypto.so.9", Version: "9.0.0", Offset: openssl.Offset{}}, Err: unknownErr}}
	err = app.checkUnknownOpenssl(nil, unknown)

	if !errors.Is(err, openssl.ErrUnknownVersion) || !strings.Contains(err.Error(), "make generate-openssl-offsets") || !strings.Contains(logs.String(), "level=ERROR") {
		state.Errorf("Test of app.checkUnknownOpenssl function failed, error should be %v naming the make command, logs: %q, error: %v", openssl.ErrUnknownVersion, logs.String(), err)
		return
	}
}

// every text is in text
func containsAll(text string, texts []string) (isAll bool) {
	isAll = true

	for _, part := range texts {
		isAll = isAll && strings.Contains(text, part)
	}

	return
}

// an app of run mode on Linux with the flags and the filter, an empty filter is none; its logs go to output
func newTestApp(ctx context.Context, flags redirect.Filter, filterText string, output *bytes.Buffer) (app App, err error) {
	var scopeFilter *filter.Filter

	if filterText != "" {
		parsed, parseErr := filter.Parse(filterText)

		if err = parseErr; err != nil {
			return
		}

		scopeFilter = &parsed
	}

	logger := slog.New(slog.NewTextHandler(output, nil))
	app = New(ctx, flags, scopeFilter, 15001, 30*time.Second, false, false, false, false, nil, "", time.Minute, 5*time.Second, "", false, "", false, 0, platform.Platform{Type: platform.LinuxType}, logger)
	return
}

// nil and empty lists are the same selection
func equalSelection(first redirect.Filter, second redirect.Filter) (isEqual bool) {
	isEqual = reflect.DeepEqual(normalize(first), normalize(second))
	return
}

func normalize(selection redirect.Filter) (normalized redirect.Filter) {
	normalized = redirect.Filter{
		UIDs:             selection.UIDs,
		Tgids:            selection.Tgids,
		DestinationCIDRs: selection.DestinationCIDRs,
		DestinationPorts: selection.DestinationPorts,
		Comms:            selection.Comms,
	}

	if len(normalized.UIDs) == 0 {
		normalized.UIDs = nil
	}

	if len(normalized.Tgids) == 0 {
		normalized.Tgids = nil
	}

	if len(normalized.DestinationCIDRs) == 0 {
		normalized.DestinationCIDRs = nil
	}

	if len(normalized.DestinationPorts) == 0 {
		normalized.DestinationPorts = nil
	}

	if len(normalized.Comms) == 0 {
		normalized.Comms = nil
	}

	return
}
