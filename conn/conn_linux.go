package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ListenUDP wraps Go's net.ListenConfig.ListenPacket and sets socket options on supported platforms.
//
// On Linux and Windows, IP_PKTINFO and IPV6_RECVPKTINFO are set to 1;
// IP_MTU_DISCOVER, IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO to disable IP fragmentation to encourage correct MTU settings.
//
// On Linux, SO_MARK is set to user-specified value.
//
// On macOS and FreeBSD, IP_DONTFRAG, IPV6_DONTFRAG are set to 1 (Don't Fragment).
func ListenUDP(network string, laddr string, fwmark int) (conn *net.UDPConn, err error, serr error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set IP_PKTINFO, IP_MTU_DISCOVER for both v4 and v6.
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
				}

				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
				}

				if network == "udp6" {
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
					}

					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
					}
				}

				if fwmark != 0 {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
						serr = fmt.Errorf("failed to set socket option SO_MARK: %w", err)
					}
				}
			})
		},
	}

	pconn, err := lc.ListenPacket(context.Background(), network, laddr)
	if err != nil {
		return
	}
	conn = pconn.(*net.UDPConn)
	return
}

// On Linux and Windows, UpdateOobCache filters out irrelevant OOB messages,
// saves IP_PKTINFO or IPV6_PKTINFO socket control messages to the OOB cache,
// and returns the updated OOB cache slice.
//
// The returned OOB cache is unchanged if no relevant control messages
// are found.
//
// On other platforms, this is a no-op.
func UpdateOobCache(oobCache, oob []byte, logger *zap.Logger) ([]byte, error) {
	// Since we only set IP_PKTINFO and/or IPV6_PKTINFO,
	// Inet4Pktinfo or Inet6Pktinfo should be the first
	// and only socket control message returned.
	// Therefore we simplify the process by not looping
	// through the OOB data.
	if len(oob) < unix.SizeofCmsghdr {
		return oobCache, fmt.Errorf("oob length %d shorter than cmsghdr length", len(oob))
	}

	cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))

	switch {
	case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_PKTINFO && len(oob) >= unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo:
		pktinfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
		// Clear destination address.
		pktinfo.Addr = [4]byte{}
		// logger.Debug("Matched Inet4Pktinfo", zap.Int32("ifindex", pktinfo.Ifindex))

	case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO && len(oob) >= unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo:
		// pktinfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
		// logger.Debug("Matched Inet6Pktinfo", zap.Uint32("ifindex", pktinfo.Ifindex))

	default:
		return oobCache, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}

	return append(oobCache[:0], oob...), nil
}

const (
	// Set GSO segmentation size.
	UDP_SEGMENT = 103

	// This socket can receive UDP GRO packets.
	UDP_GRO = 104
)

// Max number of UDP GSO segments.
//
// Source: include/linux/udp.h
const UDP_MAX_SEGMENTS = 1 << 6

// Source: include/uapi/linux/if_ether.h
const (
	ETH_DATA_LEN = 1500
	ETH_MAX_MTU  = 0xFFFF
)

// Source: include/uapi/linux/uio.h
const UIO_MAXIOV = 1024

// Source: tools/testing/selftests/net/udpgso_bench_tx.c
const MAX_NR_MSG = ETH_MAX_MTU / ETH_DATA_LEN

// SizeofUDPSegmentCmsg is the size of an 64-bit aligned
// UDP_SEGMENT socket control message.
const SizeofUDPSegmentCmsg = 24

// UDPSegmentCmsg is a socket control message of UDP_SEGMENT type,
// aligned for 64-bit platforms.
type UDPSegmentCmsg struct {
	Cmsghdr unix.Cmsghdr
	GsoSize uint16
	_       [6]byte
}

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

// DetectUDPGSO detects and returns whether UDP GSO is supported on the system.
func DetectUDPGSO(conn *net.UDPConn, logger *zap.Logger) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		logger.Warn("Failed to get syscall.RawConn", zap.Error(err))
		return false
	}

	rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, UDP_SEGMENT, 0)
	})

	if err != nil {
		logger.Debug("DetectUDPGSO: Failed to set socket option UDP_SEGMENT", zap.Error(err))
		return false
	}

	return true
}

func WriteMmsgGSOUDPAddrPort(conn *net.UDPConn, vec []unix.Iovec, oob []byte, addrPort netip.AddrPort) error {
	// Parse addrPort into SockaddrInet4/6.

	var (
		name    *byte
		namelen uint32
	)

	addr := addrPort.Addr()
	port := addrPort.Port()

	if addr.Is4() {
		rsa4 := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   addr.As4(),
		}
		p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
		p[0] = byte(port >> 8)
		p[1] = byte(port)
		name = &(*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&rsa4)))[0]
		namelen = unix.SizeofSockaddrInet4
	} else {
		rsa6 := unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Addr:   addr.As16(),
		}
		p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
		p[0] = byte(port >> 8)
		p[1] = byte(port)
		name = &(*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&rsa6)))[0]
		namelen = unix.SizeofSockaddrInet6
	}

	var msgvec []Mmsghdr

	for i := range vec {
		var mmsghdr Mmsghdr

		// Select packets for GSO.
		// j is the half-open upper bound.
		gsoSize := vec[i].Len
		j := 1
		gsoMaxSegments := UDP_MAX_SEGMENTS
		if ETH_MAX_MTU/gsoSize < uint64(gsoMaxSegments) {
			gsoMaxSegments = ETH_MAX_MTU / int(gsoSize)
		}
		for ; j < gsoMaxSegments && i+j < len(vec); j++ {
			if vec[i+j].Len < gsoSize { // Small packet. Include it in current GSO.
				j++
				break
			}

			if vec[i+j].Len > gsoSize { // Big packet. Leave it behind.
				break
			}
		}

		mmsghdr.Msghdr.Name = name
		mmsghdr.Msghdr.Namelen = namelen

		//FIXME: Consider copying selected packets into one big buffer?
		mmsghdr.Msghdr.Iov = &vec[i]
		mmsghdr.Msghdr.Iovlen = uint64(j)

		if j > 1 {
			cmsglen := len(oob) + SizeofUDPSegmentCmsg
			cmsg := make([]byte, cmsglen)
			copy(cmsg, oob)
			gsoCmsg := (*UDPSegmentCmsg)(unsafe.Pointer(&cmsg[len(oob)]))
			*gsoCmsg = UDPSegmentCmsg{
				Cmsghdr: unix.Cmsghdr{
					Len:   unix.SizeofCmsghdr + 2,
					Level: unix.IPPROTO_UDP,
					Type:  UDP_SEGMENT,
				},
				GsoSize: uint16(gsoSize),
			}
			mmsghdr.Msghdr.Control = &cmsg[0]
			mmsghdr.Msghdr.SetControllen(cmsglen)
		} else if len(oob) > 0 {
			mmsghdr.Msghdr.Control = &oob[0]
			mmsghdr.Msghdr.SetControllen(len(oob))
		}

		msgvec = append(msgvec, mmsghdr)
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var processed int

	for processed < len(msgvec) {
		rawConn.Write(func(fd uintptr) (done bool) {
			r0, _, e1 := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&msgvec[processed])), uintptr(len(msgvec)-processed), 0, 0, 0)
			if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
				return false
			}
			processed += int(r0)
			if e1 != 0 {
				err = e1
			}
			return true
		})

		if err != nil {
			return fmt.Errorf("sendmmsg failed: %w", err)
		}
	}

	return nil
}
