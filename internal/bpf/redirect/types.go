// SPDX-License-Identifier: AGPL-3.0-only

package redirect

import (
	"net/netip"
)

type Flow struct {
	OriginalDestination netip.AddrPort
	IPProtocol          uint8
	Redirected          bool
	Tgid                uint32
	UID                 uint32
	CgroupID            uint64
	Comm                string
	Client              netip.AddrPort
}
