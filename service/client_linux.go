package service

import (
	"net/netip"

	"github.com/database64128/swgp-go/conn"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (c *client) relayWgToProxyGSO(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	dequeuedPackets := make([]clientQueuedPacket, 0, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, 0, conn.UIO_MAXIOV)

	for {
		// Dequeue packets and append to dequeuedPackets.

		var (
			dequeuedPacket clientQueuedPacket
			ok             bool
		)

		dequeuedPackets = dequeuedPackets[:0]

		// Block on first dequeue op.
		dequeuedPacket, ok = <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		dequeuedPackets = append(dequeuedPackets, dequeuedPacket)

	dequeue:
		for i := 1; i < conn.UIO_MAXIOV; i++ {
			select {
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
				if !ok {
					goto cleanup
				}
				dequeuedPackets = append(dequeuedPackets, dequeuedPacket)
			default:
				break dequeue
			}
		}

		// Reslice iovec.
		iovec = iovec[:len(dequeuedPackets)]

		// Encrypt packets and add to iovec.
		for i, packet := range dequeuedPackets {
			packetBuf := *packet.bufp

			swgpPacket, err := c.handler.EncryptZeroCopy(packetBuf, packet.start, packet.length, c.maxProxyPacketSize)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				goto cleanup
			}

			iovec[i].Base = &swgpPacket[0]
			iovec[i].SetLen(len(swgpPacket))
		}

		// Batch write.
		if err := conn.WriteMmsgGSOUDPAddrPort(natEntry.proxyConn, iovec, natEntry.proxyConnOobCache, c.proxyAddr); err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

	cleanup:
		for _, packet := range dequeuedPackets {
			c.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}
}
