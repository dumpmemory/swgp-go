package service

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (c *client) setRelayFunc() {
	// Keep these dead methods for now.
	_ = c.relayWgToProxySendmmsgRing
	_ = c.relayProxyToWgSendmmsgRing

	switch c.config.BatchMode {
	case "sendmmsg", "":
		c.recvFromWgConn = c.recvFromWgConnRecvmmsg
	default:
		c.recvFromWgConn = c.recvFromWgConnGeneric
	}
}

func (c *client) recvFromWgConnRecvmmsg() {
	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()
	packetBufRecvSize := c.maxProxyPacketSize - frontOverhead - rearOverhead

	bufvec := make([]*[]byte, conn.UIO_MAXIOV)
	namevec := make([]unix.RawSockaddrInet6, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	cmsgvec := make([][]byte, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	n := conn.UIO_MAXIOV

	var (
		err             error
		recvmmsgCount   uint64
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		for i := range iovec[:n] {
			packetBufp := c.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			bufvec[i] = packetBufp
			iovec[i].Base = &packetBuf[frontOverhead]
			iovec[i].SetLen(packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = conn.Recvmmsg(c.wgConn, msgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Error(err),
			)
			n = 1
			c.packetBufPool.Put(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)

		c.mu.Lock()

		for i, msg := range msgvec[:n] {
			packetBufp := bufvec[i]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if msg.Msghdr.Controllen == 0 {
				c.logger.Warn("Skipping packet with no control message from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
				)
				c.packetBufPool.Put(packetBufp)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				c.logger.Warn("Failed to read from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				continue
			}

			wgBytesReceived += uint64(msg.Msglen)

			natEntry, ok := c.table[clientAddrPort]
			if !ok {
				proxyConn, err, serr := conn.ListenUDP("udp", "", false, c.config.ProxyFwmark)
				if err != nil {
					c.logger.Warn("Failed to start UDP listener for new UDP session",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					c.packetBufPool.Put(packetBufp)
					c.mu.Unlock()
					continue
				}
				if serr != nil {
					c.logger.Warn("An error occurred while setting socket options on proxyConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Int("proxyFwmark", c.config.ProxyFwmark),
						zap.NamedError("serr", serr),
					)
				}

				err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					c.logger.Warn("Failed to SetReadDeadline on proxyConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", c.proxyAddr),
						zap.Error(err),
					)
					c.packetBufPool.Put(packetBufp)
					c.mu.Unlock()
					continue
				}

				natEntry = &clientNatEntry{
					proxyConn:       proxyConn,
					proxyConnSendCh: make(chan queuedPacket, sendChannelCapacity),
				}

				c.table[clientAddrPort] = natEntry
			}

			var clientPktinfop *[]byte

			if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					c.logger.Warn("Failed to parse pktinfo control message from wgConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					c.packetBufPool.Put(packetBufp)
					c.mu.Unlock()
					continue
				}

				clientPktinfoCache := make([]byte, len(cmsg))
				copy(clientPktinfoCache, cmsg)
				clientPktinfop = &clientPktinfoCache
				natEntry.clientPktinfo.Store(clientPktinfop)
				natEntry.clientPktinfoCache = clientPktinfoCache

				c.logger.Debug("Updated client pktinfo",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}

			if !ok {
				c.wg.Add(2)

				go func() {
					c.relayProxyToWgSendmmsg(clientAddrPort, natEntry, clientPktinfop)

					c.mu.Lock()
					close(natEntry.proxyConnSendCh)
					delete(c.table, clientAddrPort)
					c.mu.Unlock()

					c.wg.Done()
				}()

				go func() {
					c.relayWgToProxySendmmsg(clientAddrPort, natEntry)
					natEntry.proxyConn.Close()
					c.wg.Done()
				}()

				c.logger.Info("New UDP session",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)
			}

			select {
			case natEntry.proxyConnSendCh <- queuedPacket{packetBufp, frontOverhead, int(msg.Msglen)}:
			default:
				c.logger.Debug("swgpPacket dropped due to full send channel",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)
				c.packetBufPool.Put(packetBufp)
			}
		}

		c.mu.Unlock()
	}

	for _, packetBufp := range bufvec {
		c.packetBufPool.Put(packetBufp)
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (c *client) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	rsa6 := conn.AddrPortToSockaddrInet6(c.proxyAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

main:
	for {
		var count int

		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(packetBuf, dequeuedPacket.start, dequeuedPacket.length)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)

				c.packetBufPool.Put(dequeuedPacket.bufp)

				if count == 0 {
					continue main
				}
				goto next
			}

			dequeuedPackets[count] = dequeuedPacket
			iovec[count].Base = &packetBuf[swgpPacketStart]
			iovec[count].SetLen(swgpPacketLength)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if count == vecSize {
				break
			}

		next:
			select {
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
				if !ok {
					break dequeue
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		if err := conn.WriteMsgvec(natEntry.proxyConn, msgvec[:count]); err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

		for _, packet := range dequeuedPackets[:count] {
			c.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayWgToProxySendmmsgRing(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	rsa6 := conn.AddrPortToSockaddrInet6(c.proxyAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	var (
		// Turn dequeuedPackets into a ring buffer.
		head, tail int

		// Number of messages in msgvec.
		count int

		err error

		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

main:
	for {
		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			dequeuedPacket.start, dequeuedPacket.length, err = c.handler.EncryptZeroCopy(packetBuf, dequeuedPacket.start, dequeuedPacket.length)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)

				c.packetBufPool.Put(dequeuedPacket.bufp)

				if count == 0 {
					continue main
				}
				goto next
			}

			dequeuedPackets[tail] = dequeuedPacket
			tail = (tail + 1) & sizeMask

			iovec[count].Base = &packetBuf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if tail == head {
				break
			}

		next:
			select {
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
				if !ok {
					break dequeue
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		n, err := conn.Sendmmsg(natEntry.proxyConn, msgvec[:count])
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			// Error is caused by the first packet in msgvec.
			n = 1
		}

		sendmmsgCount++
		packetsSent += uint64(n)

		// Clean up and move head forward.
		for i := 0; i < n; i++ {
			c.packetBufPool.Put(dequeuedPackets[head].bufp)
			head = (head + 1) & sizeMask
		}

		// Move unsent packets to the beginning of msgvec.
		expectedCount := count - n
		count = 0
		for i := head; i != tail; i = (i + 1) & sizeMask {
			dequeuedPacket = dequeuedPackets[i]
			packetBuf = *dequeuedPacket.bufp
			iovec[count].Base = &packetBuf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
		}
		if count != expectedCount {
			c.logger.Error("Packet count does not match ring buffer status",
				zap.Int("count", count),
				zap.Int("expectedCount", expectedCount),
			)
		}
	}

	// Exit cleanup.
	for head != tail {
		c.packetBufPool.Put(dequeuedPackets[head].bufp)
		head = (head + 1) & sizeMask
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry, clientPktinfop *[]byte) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	for i := 0; i < vecSize; i++ {
		bufvec[i] = make([]byte, c.maxProxyPacketSize)

		riovec[i].Base = &bufvec[i][0]
		riovec[i].SetLen(c.maxProxyPacketSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	for {
		nr, err := conn.Recvmmsg(natEntry.proxyConn, rmsgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}

		var ns int

		for i, msg := range rmsgvec[:nr] {
			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, c.proxyAddr) {
				c.logger.Debug("Ignoring packet from non-proxy address",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				c.logger.Warn("Packet from proxyConn discarded",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]
			wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[wgPacketStart]
			siovec[ns].SetLen(wgPacketLength)
			ns++
			wgBytesSent += uint64(wgPacketLength)
		}

		if ns == 0 {
			continue
		}

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		err = conn.WriteMsgvec(c.wgConn, smsgvec[:ns])
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgSendmmsgRing(clientAddr netip.AddrPort, natEntry *clientNatEntry, clientPktinfop *[]byte) {
	const (
		vecSize  = 64
		sizeMask = 63
	)

	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	var (
		// Tracks individual buffer's usage in bufvec.
		usage uint64

		// Current position in bufvec.
		pos int = -1
	)

	for i := 0; i < vecSize; i++ {
		bufvec[i] = make([]byte, c.maxProxyPacketSize)

		riovec[i].Base = &bufvec[i][0]
		riovec[i].SetLen(c.maxProxyPacketSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	var (
		n   int
		nr  int = vecSize
		ns  int
		err error
	)

	for {
		nr, err = conn.Recvmmsg(natEntry.proxyConn, rmsgvec[:nr])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}

		for _, msg := range rmsgvec[:nr] {
			// Advance pos to the current unused buffer.
			for {
				pos = (pos + 1) & sizeMask
				if usage>>pos&1 == 0 { // unused
					break
				}
			}

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, c.proxyAddr) {
				c.logger.Debug("Ignoring packet from non-proxy address",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				c.logger.Warn("Packet from proxyConn discarded",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[pos]
			wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[wgPacketStart]
			siovec[ns].SetLen(wgPacketLength)
			ns++
			wgBytesSent += uint64(wgPacketLength)

			// Mark buffer as used.
			usage |= 1 << pos
		}

		if ns == 0 {
			continue
		}

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		// Batch write.
		n, err = conn.Sendmmsg(c.wgConn, smsgvec[:ns])
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			n = 1
		}
		ns -= n

		sendmmsgCount++
		packetsSent += uint64(n)

		// Move unsent packets to the beginning of smsgvec.
		for i := 0; i < ns; i++ {
			siovec[i].Base = siovec[n+i].Base
			siovec[i].Len = siovec[n+i].Len
		}

		// Assign unused buffers to rmsgvec.
		nr = 0
		tpos := pos
		for i := 0; i < vecSize; i++ {
			tpos = (tpos + 1) & sizeMask

			switch {
			case usage>>tpos&1 == 0: // unused
			case n > 0: // used and sent
				usage ^= 1 << tpos // Mark as unused.
				n--
			default: // used and not sent
				continue
			}

			riovec[nr].Base = &bufvec[tpos][0]
			riovec[nr].SetLen(c.maxProxyPacketSize)
			nr++
		}
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}
