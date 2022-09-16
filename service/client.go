package service

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
)

// ClientConfig stores configurations for a swgp client service.
// It may be marshaled as or unmarshaled from JSON.
type ClientConfig struct {
	Name          string `json:"name"`
	WgListen      string `json:"wgListen"`
	WgFwmark      int    `json:"wgFwmark"`
	ProxyEndpoint string `json:"proxyEndpoint"`
	ProxyMode     string `json:"proxyMode"`
	ProxyPSK      []byte `json:"proxyPSK"`
	ProxyFwmark   int    `json:"proxyFwmark"`
	MTU           int    `json:"mtu"`
	BatchMode     string `json:"batchMode"`
}

type clientNatEntry struct {
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	proxyConn          *net.UDPConn
	proxyConnSendCh    chan queuedPacket
}

type client struct {
	config  ClientConfig
	logger  *zap.Logger
	handler packet.Handler

	wgConn    *net.UDPConn
	proxyAddr netip.AddrPort

	wgTunnelMTU        int
	maxProxyPacketSize int
	packetBufPool      *sync.Pool

	mu    sync.Mutex
	wg    sync.WaitGroup
	mwg   sync.WaitGroup
	table map[netip.AddrPort]*clientNatEntry

	recvFromWgConn func()
}

// NewClientService creates a swgp client service from the specified client config.
// Call the Start method on the returned service to start it.
func NewClientService(config ClientConfig, logger *zap.Logger) (Service, error) {
	// Require MTU to be at least 1280.
	if config.MTU < 1280 {
		return nil, ErrMTUTooSmall
	}

	c := &client{
		config: config,
		logger: logger,
		table:  make(map[netip.AddrPort]*clientNatEntry),
	}
	var err error

	// Create packet handler for user-specified proxy mode.
	c.handler, err = getPacketHandlerForProxyMode(config.ProxyMode, config.ProxyPSK)
	if err != nil {
		return nil, err
	}

	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()
	overhead := frontOverhead + rearOverhead

	// Resolve endpoint address.
	c.proxyAddr, err = conn.ResolveAddrPort(config.ProxyEndpoint)
	if err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	if addr := c.proxyAddr.Addr(); addr.Is4() || addr.Is4In6() {
		c.maxProxyPacketSize = config.MTU - IPv4HeaderLength - UDPHeaderLength
	} else {
		c.maxProxyPacketSize = config.MTU - IPv6HeaderLength - UDPHeaderLength
	}

	if c.maxProxyPacketSize <= overhead {
		return nil, fmt.Errorf("max proxy packet size %d must be greater than total overhead %d", c.maxProxyPacketSize, overhead)
	}

	c.wgTunnelMTU = (c.maxProxyPacketSize - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	// Initialize packet buffer pool.
	c.packetBufPool = &sync.Pool{
		New: func() any {
			b := make([]byte, c.maxProxyPacketSize)
			return &b
		},
	}

	c.setRelayFunc()
	return c, nil
}

// String implements the Service String method.
func (c *client) String() string {
	return c.config.Name + " swgp client service"
}

// Start implements the Service Start method.
func (c *client) Start() (err error) {
	var serr error
	c.wgConn, err, serr = conn.ListenUDP("udp", c.config.WgListen, true, c.config.WgFwmark)
	if err != nil {
		return
	}
	if serr != nil {
		c.logger.Warn("An error occurred while setting socket options on listener",
			zap.Stringer("service", c),
			zap.String("wgListen", c.config.WgListen),
			zap.Int("wgFwmark", c.config.WgFwmark),
			zap.NamedError("serr", serr),
		)
	}

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConn()
		c.mwg.Done()
	}()

	c.logger.Info("Started service",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.String("proxyEndpoint", c.config.ProxyEndpoint),
		zap.String("proxyMode", c.config.ProxyMode),
		zap.Int("wgTunnelMTU", c.wgTunnelMTU),
	)
	return
}

func (c *client) recvFromWgConnGeneric() {
	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()

	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		packetBufp := c.packetBufPool.Get().(*[]byte)
		packetBuf := *packetBufp
		plaintextBuf := packetBuf[frontOverhead : c.maxProxyPacketSize-rearOverhead]

		n, cmsgn, flags, clientAddr, err := c.wgConn.ReadMsgUDPAddrPort(plaintextBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.packetBufPool.Put(packetBufp)
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Error(err),
			)
			c.packetBufPool.Put(packetBufp)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Error(err),
			)
			c.packetBufPool.Put(packetBufp)
			continue
		}
		cmsg := cmsgBuf[:cmsgn]

		packetsReceived++
		wgBytesReceived += uint64(n)

		c.mu.Lock()

		natEntry, ok := c.table[clientAddr]
		if !ok {
			proxyConn, err, serr := conn.ListenUDP("udp", "", false, c.config.ProxyFwmark)
			if err != nil {
				c.logger.Warn("Failed to start UDP listener for new UDP session",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
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
					zap.Stringer("clientAddress", clientAddr),
					zap.Int("proxyFwmark", c.config.ProxyFwmark),
					zap.NamedError("serr", serr),
				)
			}

			err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
			if err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
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

			c.table[clientAddr] = natEntry
		}

		var clientPktinfop *[]byte

		if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse pktinfo control message from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
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
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
				zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
			)
		}

		if !ok {
			c.wg.Add(2)

			go func() {
				c.relayProxyToWgGeneric(clientAddr, natEntry, clientPktinfop)

				c.mu.Lock()
				close(natEntry.proxyConnSendCh)
				delete(c.table, clientAddr)
				c.mu.Unlock()

				c.wg.Done()
			}()

			go func() {
				c.relayWgToProxyGeneric(clientAddr, natEntry)
				natEntry.proxyConn.Close()
				c.wg.Done()
			}()

			c.logger.Info("New UDP session",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
			)
		}

		select {
		case natEntry.proxyConnSendCh <- queuedPacket{packetBufp, frontOverhead, n}:
		default:
			c.logger.Debug("swgpPacket dropped due to full send channel",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
			)
			c.packetBufPool.Put(packetBufp)
		}

		c.mu.Unlock()
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (c *client) relayWgToProxyGeneric(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range natEntry.proxyConnSendCh {
		packetBuf := *queuedPacket.bufp

		// Update proxyConn read deadline when a handshake initiation/response message is received.
		switch packetBuf[queuedPacket.start] {
		case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
			if err := natEntry.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				c.packetBufPool.Put(queuedPacket.bufp)
				continue
			}
		}

		swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(packetBuf, queuedPacket.start, queuedPacket.length)
		if err != nil {
			c.logger.Warn("Failed to encrypt WireGuard packet",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Error(err),
			)
			c.packetBufPool.Put(queuedPacket.bufp)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		_, err = natEntry.proxyConn.WriteToUDPAddrPort(swgpPacket, c.proxyAddr)
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		c.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgGeneric(clientAddr netip.AddrPort, natEntry *clientNatEntry, clientPktinfop *[]byte) {
	var (
		clientPktinfo []byte
		packetsSent   uint64
		wgBytesSent   uint64
	)

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

	packetBuf := make([]byte, c.maxProxyPacketSize)

	for {
		n, _, flags, raddr, err := natEntry.proxyConn.ReadMsgUDPAddrPort(packetBuf, nil)
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
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(raddr, c.proxyAddr) {
			c.logger.Debug("Ignoring packet from non-proxy address",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Stringer("raddr", raddr),
				zap.Error(err),
			)
			continue
		}

		wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, n)
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
		wgPacket := packetBuf[wgPacketStart : wgPacketStart+wgPacketLength]

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = c.wgConn.WriteMsgUDPAddrPort(wgPacket, clientPktinfo, clientAddr)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(wgPacketLength)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// Stop implements the Service Stop method.
func (c *client) Stop() error {
	if c.wgConn == nil {
		return nil
	}

	now := time.Now()

	if err := c.wgConn.SetReadDeadline(now); err != nil {
		return err
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	c.mwg.Wait()

	c.mu.Lock()
	for clientAddr, entry := range c.table {
		if err := entry.proxyConn.SetReadDeadline(now); err != nil {
			c.logger.Warn("Failed to SetReadDeadline on proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}
	}
	c.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	c.wg.Wait()

	return c.wgConn.Close()
}
