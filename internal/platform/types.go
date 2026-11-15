// SPDX-License-Identifier: AGPL-3.0-only

package platform

type Type string

const (
	LinuxType   Type = "linux"
	AndroidType Type = "android"
)

// SDK and Release come from /system/build.prop (ro.build.version.sdk, ro.build.version.release), 0 and empty on Linux or when it can't be read
// DataDirectory holds the files decerter keeps between runs, such as the netd hook state on Android
// APISocket is the default of the control API socket, a name starting with @ is an abstract unix socket
type Platform struct {
	Type          Type
	SDK           int
	Release       string
	DataDirectory string
	APISocket     string
}

// an executable file mapping of a process, from /proc/<pid>/maps: the mapped file as the process sees it and the file offset the mapping starts at
type Mapping struct {
	Path   string
	Offset uint64
}
