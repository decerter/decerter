// SPDX-License-Identifier: AGPL-3.0-only

package android

import (
	"errors"
)

var (
	ErrPackagesList     = errors.New("could not parse packages.list")
	ErrUnknownPackage   = errors.New("unknown package")
	ErrNoADB            = errors.New("could not find adb: install the Android SDK platform-tools and set ANDROID_HOME, or put adb on PATH")
	ErrADB              = errors.New("adb failed")
	ErrNoDevice         = errors.New("no such device")
	ErrDeviceState      = errors.New("device is not ready")
	ErrSeveralDevices   = errors.New("several devices are attached, pick one with --serial")
	ErrNoEmulator       = errors.New("could not find the emulator: install the Android SDK emulator and set ANDROID_HOME")
	ErrUnknownAVD       = errors.New("unknown AVD")
	ErrBoot             = errors.New("the emulator did not boot")
	ErrNoRoot           = errors.New("no root on the device")
	ErrDeviceInfo       = errors.New("could not read the device properties")
	ErrUnsupportedABI   = errors.New("unsupported ABI")
	ErrOldAndroid       = errors.New("the Android release is too old")
	ErrOldKernel        = errors.New("kernel is too old")
	ErrKernelVersion    = errors.New("could not parse the kernel release")
	ErrBinary           = errors.New("binary does not fit the device")
	ErrDecerterRunning  = errors.New("decerter runs on the device, stop it first")
	ErrBinaryPath       = errors.New("the binary path on the device is taken")
	ErrBinaryNotWorking = errors.New("the pushed binary does not run")
	ErrForward          = errors.New("could not forward the api socket")
	ErrInstallDirectory = errors.New("could not look for the install directory")
	ErrChromeFlags      = errors.New("could not write or check Chrome's flags file")
)
