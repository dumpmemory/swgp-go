package conn

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func setSendBufferSize(fd, size int) error {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF: %w", err)
	}
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF: %w", err)
	}
	return nil
}

const (
	IP_MTU_DISCOVER   = 71
	IPV6_MTU_DISCOVER = 71
)

// enum PMTUD_STATE from ws2ipdef.h
const (
	IP_PMTUDISC_NOT_SET = iota
	IP_PMTUDISC_DO
	IP_PMTUDISC_DONT
	IP_PMTUDISC_PROBE
	IP_PMTUDISC_MAX
)

func setPMTUD(fd int, network string) error {
	switch network {
	case "tcp4", "udp4":
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
		}
	case "tcp6", "udp6":
		// For dual-stack IPv6 sockets, both IP_MTU_DISCOVER and IPV6_MTU_DISCOVER need to be set.
		// However, if IPV6_V6ONLY is set to true, setting IP_MTU_DISCOVER will fail with WSAEINVAL.
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil && err != windows.WSAEINVAL {
			return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

// Implementation inspired by:
// https://github.com/quinn-rs/quinn/blob/main/quinn-udp/src/windows.rs

func probeUDPGSOSupport(fd int, info *SocketInfo) {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_UDP, windows.UDP_SEND_MSG_SIZE, 0); err == nil {
		// As "empirically found on Windows 11 x64" by quinn.
		info.MaxUDPGSOSegments = 512
	}
}

func setUDPGenericReceiveOffload(fd int, info *SocketInfo) {
	// Both quinn and msquic set this to 65535.
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_UDP, windows.UDP_RECV_MAX_COALESCED_SIZE, 65535); err == nil {
		info.UDPGenericReceiveOffload = true
	}
}

func setRecvPktinfo(fd int, network string) error {
	switch network {
	case "udp4":
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
		}
	case "udp6":
		// This behaves just like IP_MTU_DISCOVER. See comments above for more details.
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1); err != nil && err != windows.WSAEINVAL {
			return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
		}
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_PKTINFO: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendProbeUDPGSOSupportFunc(lso.ProbeUDPGSOSupport).
		appendSetUDPGenericReceiveOffloadFunc(lso.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}
