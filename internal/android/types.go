// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"time"
)

type RootType string

const (
	// adbd runs as root after adb root: every adb shell is root, the emulator's google_apis images and userdebug builds
	ADBRootType RootType = "adb root"
	// a rooted production build (Magisk, KernelSU): adbd stays shell, root commands go through su -c
	SuRootType RootType = "su"
)

const (
	// the oldest Android whose netd hooks decerter shares, and the oldest GKI kernel: android15-6.6
	minimumSDK           int = 35
	minimumAndroidKernel int = 15
	minimumKernelMajor   int = 6
	minimumKernelMinor   int = 6
	// apps get uids from here on, a uid below it is a system uid shared by many processes
	firstApplicationUID uint32 = 10000
	// the field of packages.list with the versionCode, counted from 0
	versionCodeField int = 7
	// the package name of Trichrome's static shared library contains this, Chrome and WebView link their native code from it
	trichromeLibraryName string = "trichromelibrary"
	// how many installed packages an unknown name lists
	suggestionCount int = 5
	// adb forward to the abstract socket of the control API, the name without the @
	apiSocketName string = "decerter-api"
	// the console ports of the emulators adb looks for: 5554 to 5584, even, the adb port is the next one
	firstEmulatorPort int = 5554
	lastEmulatorPort  int = 5584
	// every adb call is killed after this long unless it says otherwise, a push of decerter takes a few seconds
	adbTimeout    time.Duration = 30 * time.Second
	pushTimeout   time.Duration = 2 * time.Minute
	rootTimeout   time.Duration = time.Minute
	bootTimeout   time.Duration = 5 * time.Minute
	pollInterval  time.Duration = 250 * time.Millisecond
	binaryVersion string        = "--version"
)

// one line of /data/system/packages.list: the package name, the uid of its app in user 0 and its versionCode, 0 when the line has none
type Package struct {
	Name        string
	UID         uint32
	VersionCode int64
}

// one line of adb devices: State is device when adb can use it, otherwise offline, unauthorized, no permissions (…)
type Device struct {
	Serial string
	State  string
}

// one line of adb forward --list
type Forward struct {
	Serial string
	Local  string
	Remote string
}

// what decerter android setup needs to know of a device, from getprop, uname -r and id -u
type DeviceInfo struct {
	ABI        string
	Release    string
	SDK        int
	Kernel     string
	Model      string
	BuildType  string
	IsEmulator bool
	UID        string
}

// the kernel release of uname -r: 6.6.50-android15-8-g… is 6, 6 and 15; Android is 0 for a kernel without the GKI branch in its name
type Kernel struct {
	Major   int
	Minor   int
	Android int
}

// the adb client and the device it talks to; Root says how root commands run on it, empty before rooting
type ADB struct {
	Path   string
	Serial string
	Root   RootType
}

// decerter android setup: Serial or AVD picks the device, Binary overrides the binary pushed, Port the host port of the forward (0 keeps an existing one or lets adb pick),
// Package is checked on the device and goes into the printed command; Executable is this decerter, Command how the user called it
type Options struct {
	Serial     string
	AVD        string
	Binary     string
	Port       uint16
	Package    string
	Executable string
	Command    string
}
