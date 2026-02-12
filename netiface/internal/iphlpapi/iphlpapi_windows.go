package iphlpapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetUnicastIpAddressTable = modiphlpapi.NewProc("GetUnicastIpAddressTable")
)

// MibUnicastIpAddressTable contains a table of unicast IP address entries. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_table.
type MibUnicastIpAddressTable struct {
	NumEntries uint32
	Table      [1]windows.MibUnicastIpAddressRow
}

// Rows returns the unicast IP address entries in the table.
func (t *MibUnicastIpAddressTable) Rows() []windows.MibUnicastIpAddressRow {
	return unsafe.Slice(&t.Table[0], t.NumEntries)
}

func GetUnicastIpAddressTable(family uint16, table **MibUnicastIpAddressTable) (errcode error) {
	r0, _, _ := syscall.SyscallN(procGetUnicastIpAddressTable.Addr(), uintptr(family), uintptr(unsafe.Pointer(table)))
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}
