//go:build !linux

package service

import "net/netip"

func (c *client) relayWgToProxyGSO(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	c.logger.Panic("Unreachable: Current OS does not support UDP GSO")
}
