// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/decerter/decerter/internal/tls/openssl"
)

const (
	// the distro images run their client with this command
	dockerName string = "docker"
	// a test decerter is stopped after this long when nothing else stopped it
	decerterCommandTimeout time.Duration = 60 * time.Second
	// how long a test decerter may take to load and attach
	decerterReadyTimeout time.Duration = 20 * time.Second
	// where the container sees the directory of the test client
	clientMount string = "/decerter"
	// the uid and gid of nobody in the images, a client that decerter must not select
	containerNobody string = "65534:65534"
)

// a distribution image whose OpenSSL 3 or 4 is checked against the offsets table
// Image is built from Base with Build when it is missing; empty Base means Image is pulled by hand (docker pull); Libssl is the soname of the image's
// default OpenSSL, libcrypto has the same suffix; Architectures lists the only architectures the image is published for, empty is every one
type distroImage struct {
	Name          string
	Image         string
	Base          string
	Build         string
	Libssl        string
	Architectures []string
}

// how a distro client runs: on the host with the copied libraries, or inside its container as the same uid
type clientPlace string

const (
	HostClientPlace      clientPlace = "host"
	ContainerClientPlace clientPlace = "container"
	// inside the container too, without --libssl: decerter finds the container's libssl in the maps of a selected process
	MappedClientPlace clientPlace = "mapped"
)

var (
	// Fedora 45 ships OpenSSL 4.0 as libssl.so.4, its OpenSSL 3 is the openssl3-libs compat package; Kali, Parrot and BlackArch (Arch) are the pentest
	// distributions, BlackArch is published for amd64 only
	distroImages = []distroImage{
		{Name: "ubuntu-24.04", Image: "ubuntu:24.04", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "debian-13", Image: "debian:13", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "fedora", Image: "fedora", Base: "", Build: "", Libssl: "libssl.so.4", Architectures: nil},
		{Name: "fedora-openssl3", Image: "decerter-e2e/fedora-openssl3", Base: "fedora", Build: "RUN [ -e /usr/lib64/libssl.so.3 ] || dnf -y install openssl3-libs && dnf clean all", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "almalinux-10", Image: "almalinux:10", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "kali-rolling", Image: "kalilinux/kali-rolling", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "parrot-core", Image: "parrotsec/core", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: nil},
		{Name: "blackarch", Image: "blackarchlinux/blackarch", Base: "", Build: "", Libssl: "libssl.so.3", Architectures: []string{"amd64"}},
	}
	// where an image keeps its libssl, the first one that has it wins
	distroLibraryDirectories = []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib"}
)

// a distro client setup: the copied libraries with the client linked against them, and the running container with the same client
type distroClient struct {
	Directory        string
	LibraryDirectory string
	Libssl           string
	Libcrypto        string
	Container        string
	ContainerRoot    string
}

// Test if decerter keylog prints the key log lines a client of each distro's default OpenSSL (3 or 4) writes to SSLKEYLOGFILE, TLS 1.2 and 1.3, for the copied libraries on the host, for the client inside the container selected by its uid, and for the container's libssl found without --libssl in the maps of a selected process, and run --decrypt prints the requests.
func TestOpenSSLDistroPositive(state *testing.T) {
	if _, err := exec.LookPath(dockerName); err != nil {
		state.Skipf("Test of the distro OpenSSL libraries skipped, no docker: %s", err.Error())
	}

	compiler, err := exec.LookPath("cc")

	if err != nil {
		state.Skipf("Test of the distro OpenSSL libraries skipped, no C compiler for the test client: %s", err.Error())
	}

	server := startServer(state, serverConfig{Certificate: &rsaCertificate, Version: 0})
	serverURL, err := url.Parse(server.URL)

	if err != nil {
		state.Fatalf("Could not parse the test server URL %s, error: %s", server.URL, err.Error())
	}

	for _, image := range distroImages {
		state.Run(image.Name, func(state *testing.T) {
			if (len(image.Architectures) != 0) && !slices.Contains(image.Architectures, runtime.GOARCH) {
				state.Skipf("Test of the distro OpenSSL libraries skipped for %s, %s is published for %s only", image.Name, image.Image, strings.Join(image.Architectures, ", "))
			}

			reason := prepareImage(state.Context(), image)

			if reason != "" {
				state.Skipf("Test of the distro OpenSSL libraries skipped for %s: %s", image.Name, reason)
			}

			client := startDistroClient(state, image, compiler)

			for _, place := range []clientPlace{HostClientPlace, ContainerClientPlace, MappedClientPlace} {
				state.Run(string(place), func(state *testing.T) {
					libssl := ""

					switch place {
					case HostClientPlace:
						libssl = filepath.Join(client.Directory, client.Libssl)

						if reason := hostRunReason(state.Context(), client); reason != "" {
							state.Skipf("Test of the distro OpenSSL libraries skipped on the host for %s, the container case covers it: %s", image.Name, reason)
						}
					case ContainerClientPlace:
						libssl = filepath.Join(client.ContainerRoot, client.LibraryDirectory, client.Libssl)
					default:
						// a client that waits in its handshake keeps the container's libssl mapped while decerter starts
						holdMappedLibrary(state, client)
					}

					testDistroKeylog(state, client, place, libssl, serverURL.Port())
					testDistroDecrypt(state, client, place, libssl, serverURL.Port(), image.Name)
				})
			}
		})
	}
}

// Test if decerter keylog refuses an OpenSSL version the offsets table does not have before it attaches, naming the nearest known version and the make command: the host's OpenSSL with major version 9, and Fedora's OpenSSL 4.0.3 as 4.0.9.
func TestOpenSSLDistroNegative(state *testing.T) {
	state.Run("host", func(state *testing.T) {
		libraries, err := openssl.FindLibssl("")

		if err != nil {
			state.Skipf("Test of an unknown OpenSSL version skipped, no OpenSSL 3 or 4 on this host: %s", err.Error())
		}

		version, err := openssl.DetectVersion(libraries[0].Libcrypto)

		if err != nil {
			state.Fatalf("Could not detect the OpenSSL version of %s, error: %s", libraries[0].Libcrypto, err.Error())
		}

		testUnknownVersion(state, libraries[0].Libssl, libraries[0].Libcrypto, version, "9"+version[1:], "the nearest known version is ")
	})

	state.Run("openssl-4", func(state *testing.T) {
		image := distroImages[slices.IndexFunc(distroImages, func(image distroImage) (isFedora bool) {
			isFedora = (image.Name == "fedora")
			return
		})]

		if _, err := exec.LookPath(dockerName); err != nil {
			state.Skipf("Test of an unknown OpenSSL 4 version skipped, no docker: %s", err.Error())
		}

		if reason := prepareImage(state.Context(), image); reason != "" {
			state.Skipf("Test of an unknown OpenSSL 4 version skipped: %s", reason)
		}

		directory := state.TempDir()
		client := distroClient{Directory: "", LibraryDirectory: "", Libssl: image.Libssl, Libcrypto: strings.Replace(image.Libssl, "libssl", "libcrypto", 1), Container: "", ContainerRoot: ""}
		created, err := runCommand(state.Context(), dockerName, "create", image.Image)

		if err != nil {
			state.Fatalf("Could not create a container of %s, error: %s", image.Image, err.Error())
		}

		err = copyLibraries(state.Context(), strings.TrimSpace(created), directory, &client)
		_, removeErr := runCommand(state.Context(), dockerName, "rm", strings.TrimSpace(created))

		if err = errors.Join(err, removeErr); err != nil {
			state.Fatalf("Could not copy the OpenSSL libraries of %s, error: %s", image.Image, err.Error())
		}

		libcrypto := filepath.Join(directory, client.Libcrypto)
		version, err := openssl.DetectVersion(libcrypto)

		if (err != nil) || !strings.HasPrefix(version, "4.0.") {
			state.Fatalf("Could not detect OpenSSL 4.0 in %s, version: %s, error: %v", libcrypto, version, err)
		}

		testUnknownVersion(state, filepath.Join(directory, client.Libssl), libcrypto, version, "4.0.9", "the nearest known version is 4.0.")
	})
}

// copy libssl and libcrypto with unknown in place of version in the version string, the same length keeps the ELF intact, and check that decerter keylog
// with --libssl fails before attaching, naming unknown and nearest
func testUnknownVersion(state *testing.T, libsslPath string, libcryptoPath string, version string, unknown string, nearest string) {
	directory := state.TempDir()
	libssl, err := os.ReadFile(libsslPath)

	if err != nil {
		state.Fatalf("Could not read %s, error: %s", libsslPath, err.Error())
	}

	libcrypto, err := os.ReadFile(libcryptoPath)

	if err != nil {
		state.Fatalf("Could not read %s, error: %s", libcryptoPath, err.Error())
	}

	libcrypto = bytes.Replace(libcrypto, []byte("OpenSSL "+version), []byte("OpenSSL "+unknown), 1)
	changedLibssl := filepath.Join(directory, filepath.Base(libsslPath))
	err = errors.Join(os.WriteFile(changedLibssl, libssl, 0o644), os.WriteFile(openssl.LibcryptoPath(changedLibssl), libcrypto, 0o644))

	if err != nil {
		state.Fatalf("Could not write the changed libraries, error: %s", err.Error())
	}

	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Could not find the test binary, error: %s", err.Error())
	}

	commandCtx, cancel := context.WithTimeout(state.Context(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(commandCtx, executable, "keylog", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--libssl", changedLibssl)
	command.Env = []string{decerterCommandEnvironment + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	output, err := command.CombinedOutput()
	expected := []string{openssl.ErrUnknownVersion.Error() + ": " + unknown + " on " + runtime.GOARCH, nearest, "run make generate-openssl-offsets"}

	for _, text := range expected {
		if (err == nil) || !strings.Contains(string(output), text) || strings.Contains(string(output), "Attached secrets uprobe") {
			state.Errorf("Test of an unknown OpenSSL version failed, decerter keylog should fail before attaching with %q, output: %s, error: %v", text, output, err)
			return
		}
	}
}

// keylog mode: the lines of the client's SSLKEYLOGFILE, without EXPORTER_SECRET which decerter does not keep, and nothing of a client run as another uid
func testDistroKeylog(state *testing.T, client distroClient, place clientPlace, libssl string, port string) {
	keyLogPath := filepath.Join(client.Directory, "keylog", string(place)+".log")
	stdout, stop := startDecerterCommand(state, distroReady(place, "Attached secrets uprobe"), distroArguments(libssl, "keylog", "--uid", strconv.FormatUint(uint64(testUser.UID), 10))...)
	clientKeyLog := []string{}

	for _, version := range []string{"1.2", "1.3"} {
		output, runErr := runDistroClient(state.Context(), client, place, false, keyLogPath, port, version, "/keylog")

		if runErr != nil {
			state.Fatalf("Test of the distro keylog failed, TLS %s, error: %s", version, runErr.Error())
		}

		if !strings.Contains(output, "/keylog") {
			state.Fatalf("Test of the distro keylog failed, TLS %s, the response should have the path, output: %q", version, output)
		}
	}

	// the other uid's secrets must not show up
	_, err := runDistroClient(state.Context(), client, place, true, "", port, "1.3", "/other")

	if err != nil {
		state.Fatalf("Test of the distro keylog failed, the client as another user, error: %s", err.Error())
	}

	err = stop()

	if err != nil {
		state.Fatalf("Could not stop decerter keylog, error: %s", err.Error())
	}

	written, err := os.ReadFile(keyLogPath)

	if err != nil {
		state.Fatalf("Could not read the client key log, error: %s", err.Error())
	}

	// a library built with enable-sslkeylog (AlmaLinux 10) writes SSLKEYLOGFILE itself too, so each line comes twice
	for _, line := range keyLogLines(string(written)) {
		if !strings.HasPrefix(line, "EXPORTER_SECRET ") && !slices.Contains(clientKeyLog, line) {
			clientKeyLog = append(clientKeyLog, line)
		}
	}

	decerterKeyLog := keyLogLines(stdout.String())
	slices.Sort(clientKeyLog)
	slices.Sort(decerterKeyLog)

	// TLS 1.2 has one CLIENT_RANDOM line, TLS 1.3 four traffic secret lines
	if (len(clientKeyLog) != 5) || !slices.Equal(clientKeyLog, decerterKeyLog) {
		state.Errorf("Test of the distro keylog failed, decerter keylog should print the client's key log, decerter: %q, client: %q", decerterKeyLog, clientKeyLog)
		return
	}
}

// run --decrypt: the request of each TLS version in the plaintext output
func testDistroDecrypt(state *testing.T, client distroClient, place clientPlace, libssl string, port string, name string) {
	stdout, stop := startDecerterCommand(state, distroReady(place, "Redirecting flows"), distroArguments(libssl, "run", "--uid", strconv.FormatUint(uint64(testUser.UID), 10), "--decrypt")...)
	paths := map[string]string{}

	for _, version := range []string{"1.2", "1.3"} {
		paths[version] = fmt.Sprintf("/decerter-%s-%s-%s", name, place, version)
		output, runErr := runDistroClient(state.Context(), client, place, false, "", port, version, paths[version])

		if (runErr != nil) || !strings.Contains(output, paths[version]) {
			state.Fatalf("Test of the distro decrypt failed, TLS %s, the response should have the path, output: %q, error: %v", version, output, runErr)
		}
	}

	err := stop()

	if err != nil {
		state.Fatalf("Could not stop decerter run, error: %s", err.Error())
	}

	printed := stdout.String()

	for version, path := range paths {
		if !strings.Contains(printed, "version=TLS"+version) || !strings.Contains(printed, "GET "+path+" HTTP/1.1") {
			state.Errorf("Test of the distro decrypt failed, TLS %s, decerter should print the request %s, output: %q", version, path, printed)
			return
		}
	}
}

// the decerter arguments with --libssl, without it for the mapped place (empty libssl)
func distroArguments(libssl string, arguments ...string) (withLibssl []string) {
	withLibssl = arguments

	if libssl != "" {
		withLibssl = append(withLibssl, "--libssl", libssl)
	}

	return
}

// what the log line decerter is ready at has in it; in keylog mode without --libssl the host's own libssl is attached first, so the mapped place waits for
// the container's (run mode logs its ready line after every attach)
func distroReady(place clientPlace, ready string) (texts []string) {
	texts = []string{ready}

	if (place == MappedClientPlace) && (ready == "Attached secrets uprobe") {
		texts = append(texts, "/root/")
	}

	return
}

// start the test client inside the container against a listener that accepts and never answers, so it waits in its handshake with the container's
// libssl mapped; it is a process of the selected uid, so decerter finds the library in its maps; the client leaves when the test closes the connection
func holdMappedLibrary(state *testing.T, client distroClient) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")

	if err != nil {
		state.Fatalf("Could not listen for the waiting client, error: %s", err.Error())
	}

	acceptedChannel := make(chan net.Conn, 1)
	waitGroup := sync.WaitGroup{}

	// waiting client acceptor
	waitGroup.Go(func() {
		connection, acceptErr := listener.Accept()

		if acceptErr != nil {
			close(acceptedChannel)
			return
		}

		acceptedChannel <- connection
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())

	if err != nil {
		state.Fatalf("Could not read the port of the listener, error: %s", err.Error())
	}

	command := exec.Command(dockerName, "exec", "--user", fmt.Sprintf("%d:%d", testUser.UID, testUser.GID), client.Container, filepath.Join(clientMount, "openssl_client"), "127.0.0.1", port, "1.3", "/wait")
	err = command.Start()

	if err != nil {
		state.Fatalf("Could not start the waiting client, error: %s", err.Error())
	}

	var connection net.Conn

	select {
	case connection = <-acceptedChannel:
	case <-time.After(commandTimeout):
	}

	state.Cleanup(func() {
		closeErr := listener.Close()

		if connection != nil {
			closeErr = errors.Join(closeErr, connection.Close())
		}

		waitGroup.Wait()

		// the client fails its handshake when the connection closes
		if waitErr := command.Wait(); (closeErr != nil) || (waitErr == nil) {
			state.Errorf("Could not stop the waiting client, error: %v, the client should fail its handshake, exit: %v", closeErr, waitErr)
		}
	})

	if connection == nil {
		state.Fatalf("Could not start the waiting client, it did not connect in %s", commandTimeout)
	}
}

// the image is there, or it is built from a base that is there; a non-empty reason skips the image
func prepareImage(ctx context.Context, image distroImage) (reason string) {
	if _, err := runCommand(ctx, dockerName, "image", "inspect", image.Image); err == nil {
		return
	}

	if image.Base == "" {
		reason = fmt.Sprintf("no image %s, run docker pull %s", image.Image, image.Image)
		return
	}

	if _, err := runCommand(ctx, dockerName, "image", "inspect", image.Base); err != nil {
		reason = fmt.Sprintf("no image %s, run docker pull %s", image.Base, image.Base)
		return
	}

	// a package install takes longer than commandTimeout
	buildCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(buildCtx, dockerName, "build", "--quiet", "--tag", image.Image, "-")
	command.Stdin = strings.NewReader(fmt.Sprintf("FROM %s\n%s\n", image.Base, image.Build))
	output, err := command.CombinedOutput()

	if err != nil {
		reason = fmt.Sprintf("could not build %s from %s: %s: %s", image.Image, image.Base, err.Error(), strings.TrimSpace(string(output)))
		return
	}

	return
}

// copy the image's libssl and libcrypto out of the image (docker create + docker cp), link the test client against them, and start the image with the client mounted as the test user
func startDistroClient(state *testing.T, image distroImage, compiler string) (client distroClient) {
	ctx := state.Context()
	directory, err := os.MkdirTemp("", "decerter-openssl-")

	if err != nil {
		state.Fatalf("Could not make the client directory, error: %s", err.Error())
	}

	state.Cleanup(func() {
		if removeErr := os.RemoveAll(directory); removeErr != nil {
			state.Errorf("Could not remove the client directory, error: %s", removeErr.Error())
		}
	})

	// the test user loads the libraries and writes the key log
	keyLogDirectory := filepath.Join(directory, "keylog")
	err = errors.Join(os.Chmod(directory, 0o755), os.Mkdir(keyLogDirectory, 0o755), os.Chown(keyLogDirectory, int(testUser.UID), int(testUser.GID)))

	if err != nil {
		state.Fatalf("Could not prepare the client directory, error: %s", err.Error())
	}

	created, err := runCommand(ctx, dockerName, "create", image.Image)

	if err != nil {
		state.Fatalf("Could not create a container of %s, error: %s", image.Image, err.Error())
	}

	created = strings.TrimSpace(created)
	client.Libssl = image.Libssl
	client.Libcrypto = strings.Replace(image.Libssl, "libssl", "libcrypto", 1)
	err = copyLibraries(ctx, created, directory, &client)
	_, removeErr := runCommand(ctx, dockerName, "rm", created)

	if err = errors.Join(err, removeErr); err != nil {
		state.Fatalf("Could not copy the OpenSSL libraries of %s, error: %s", image.Image, err.Error())
	}

	client.Directory = directory
	// gnu17 keeps glibc's C23 strtol away, so the client needs nothing newer than glibc 2.34
	_, err = runCommand(ctx, compiler, "-std=gnu17", "-O2", "-Wall", "-Werror", "-o", filepath.Join(directory, "openssl_client"), filepath.Join("assets", "openssl_client.c"), "-L"+directory, "-l:"+client.Libssl, "-l:"+client.Libcrypto)

	if err != nil {
		state.Fatalf("Could not build the test client against %s, error: %s", image.Image, err.Error())
	}

	// the same uid as the host test user, on the host network so the test server and the redirect are the host's
	started, err := runCommand(ctx, dockerName, "run", "--detach", "--rm", "--network", "host", "--user", fmt.Sprintf("%d:%d", testUser.UID, testUser.GID), "--volume", directory+":"+clientMount, image.Image, "sleep", "600")

	if err != nil {
		state.Fatalf("Could not start a container of %s, error: %s", image.Image, err.Error())
	}

	client.Container = strings.TrimSpace(started)

	state.Cleanup(func() {
		if _, stopErr := runCommand(context.Background(), dockerName, "rm", "--force", client.Container); stopErr != nil {
			state.Errorf("Could not remove the container of %s, error: %s", image.Image, stopErr.Error())
		}
	})

	pid, err := runCommand(ctx, dockerName, "inspect", "--format", "{{.State.Pid}}", client.Container)

	if err != nil {
		state.Fatalf("Could not read the pid of the container of %s, error: %s", image.Image, err.Error())
	}

	// the uprobe goes on the library of the container's root file system, the kernel resolves the overlay to the file the client maps
	client.ContainerRoot = filepath.Join("/proc", strings.TrimSpace(pid), "root")
	return
}

// the first library directory of the image that has the client's libssl, both libraries copied with their symlinks followed
func copyLibraries(ctx context.Context, container string, directory string, client *distroClient) (err error) {
	for _, libraryDirectory := range distroLibraryDirectories {
		_, copyErr := runCommand(ctx, dockerName, "cp", "--follow-link", container+":"+filepath.Join(libraryDirectory, client.Libssl), directory)

		if copyErr != nil {
			continue
		}

		_, err = runCommand(ctx, dockerName, "cp", "--follow-link", container+":"+filepath.Join(libraryDirectory, client.Libcrypto), directory)

		if err != nil {
			return
		}

		client.LibraryDirectory = libraryDirectory
		err = errors.Join(os.Chmod(filepath.Join(directory, client.Libssl), 0o644), os.Chmod(filepath.Join(directory, client.Libcrypto), 0o644))
		return
	}

	err = fmt.Errorf("no %s in %s", client.Libssl, strings.Join(distroLibraryDirectories, ", "))
	return
}

// why the copied libraries can't load on this host, empty when they can: the client without arguments prints its usage and leaves with 2, a dynamic linker error leaves with 127
func hostRunReason(ctx context.Context, client distroClient) (reason string) {
	command := exec.CommandContext(ctx, filepath.Join(client.Directory, "openssl_client"))
	command.Env = []string{"LD_LIBRARY_PATH=" + client.Directory}
	output, err := command.CombinedOutput()

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && (exitErr.ExitCode() == 2) {
		return
	}

	reason = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(output)))
	return
}

// run the test client against the test server on 127.0.0.1:port as the test user, or as another user; keyLogPath empty writes no key log
func runDistroClient(ctx context.Context, client distroClient, place clientPlace, isOtherUser bool, keyLogPath string, port string, version string, path string) (output string, err error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	arguments := []string{"127.0.0.1", port, version, path}
	var command *exec.Cmd

	switch place {
	case HostClientPlace:
		runAs := testUser

		if isOtherUser {
			runAs = otherUser
		}

		command = exec.CommandContext(commandCtx, filepath.Join(client.Directory, "openssl_client"), arguments...)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runAs.UID, Gid: runAs.GID, Groups: []uint32{}, NoSetGroups: false}}
		command.Dir = "/"
		command.Env = []string{"LD_LIBRARY_PATH=" + client.Directory, "SSLKEYLOGFILE=" + keyLogPath}
	default:
		user := fmt.Sprintf("%d:%d", testUser.UID, testUser.GID)

		if isOtherUser {
			user = containerNobody
		}

		// the key log directory is mounted with the client
		containerKeyLog := ""

		if keyLogPath != "" {
			containerKeyLog = filepath.Join(clientMount, strings.TrimPrefix(keyLogPath, client.Directory))
		}

		command = exec.CommandContext(commandCtx, dockerName, append([]string{"exec", "--user", user, "--env", "SSLKEYLOGFILE=" + containerKeyLog, client.Container, filepath.Join(clientMount, "openssl_client")}, arguments...)...)
	}

	command.WaitDelay = time.Second
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()

	if err != nil {
		err = fmt.Errorf("openssl_client %s on the %s: %w: %s", strings.Join(arguments, " "), place, err, strings.TrimSpace(stderr.String()))
		return
	}

	output = stdout.String()
	return
}

// run the test binary as decerter with the arguments until stop, which interrupts it and waits; it returns once a log line has every text of ready in it, stdout is decerter's output
func startDecerterCommand(state *testing.T, ready []string, arguments ...string) (stdout *lockedBuffer, stop func() error) {
	executable, err := os.Executable()

	if err != nil {
		state.Fatalf("Could not find the test binary, error: %s", err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), decerterCommandTimeout)
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{decerterCommandEnvironment + "=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	command.Cancel = func() (cancelErr error) {
		cancelErr = command.Process.Signal(os.Interrupt)
		return
	}
	command.WaitDelay = 5 * time.Second
	stdout = &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	command.Stdout = stdout
	stderr, err := command.StderrPipe()

	if err != nil {
		cancel()
		state.Fatalf("Could not make the stderr of decerter, error: %s", err.Error())
	}

	err = command.Start()

	if err != nil {
		cancel()
		state.Fatalf("Could not start decerter %s, error: %s", strings.Join(arguments, " "), err.Error())
	}

	// true at the ready line, false when decerter left before it
	readyChannel := make(chan bool, 1)
	logs := &lockedBuffer{mutex: &sync.Mutex{}, buffer: &bytes.Buffer{}}
	waitGroup := sync.WaitGroup{}

	// decerter log reader, reports the ready line and keeps the logs for the error messages
	waitGroup.Go(func() {
		scanner := bufio.NewScanner(stderr)
		isReady := false

		for scanner.Scan() {
			if _, writeErr := fmt.Fprintln(logs, scanner.Text()); writeErr != nil {
				break
			}

			if !isReady && containsAll(scanner.Text(), ready) {
				isReady = true
				readyChannel <- true
			}
		}

		if !isReady {
			readyChannel <- false
		}

		// the rest of stderr has to be read for Wait
		if _, copyErr := io.Copy(io.Discard, stderr); copyErr != nil {
			return
		}
	})

	stop = sync.OnceValue(func() (stopErr error) {
		cancel()
		stopErr = command.Wait()
		waitGroup.Wait()

		// Wait reports the cancel that interrupted decerter, a clean exit after it is a clean stop
		if (command.ProcessState != nil) && command.ProcessState.Success() {
			stopErr = nil
		}

		if stopErr != nil {
			stopErr = fmt.Errorf("decerter %s: %w: %s", strings.Join(arguments, " "), stopErr, logs.String())
		}

		return
	})

	state.Cleanup(func() {
		if stopErr := stop(); stopErr != nil {
			state.Errorf("Could not stop decerter, error: %s", stopErr.Error())
		}
	})

	isReady := false

	select {
	case isReady = <-readyChannel:
	case <-time.After(decerterReadyTimeout):
	}

	if !isReady {
		stopErr := stop()
		state.Fatalf("Could not start decerter %s, no %q log line in %s, error: %v, logs: %s", strings.Join(arguments, " "), ready, decerterReadyTimeout, stopErr, logs.String())
	}

	return
}

// every text is in line
func containsAll(line string, texts []string) (isAll bool) {
	isAll = !slices.ContainsFunc(texts, func(text string) (isMissing bool) {
		isMissing = !strings.Contains(line, text)
		return
	})
	return
}
