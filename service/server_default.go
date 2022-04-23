//go:build !linux

package service

import "net/netip"

func (s *server) relayProxyToWgGSO(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	s.logger.Panic("Unreachable: Current OS does not support UDP GSO")
}
