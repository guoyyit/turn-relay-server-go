package turn

import (
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// handleIndication processes a Send indication (RFC 5766 section 2.4).
// Indications carry no MESSAGE-INTEGRITY; authorisation is the allocation
// (source address binding) plus the permission for the peer.
func (s *Server) handleIndication(msg *stun.Message, src *net.UDPAddr) {
	if msg.Method() != methodSend {
		return
	}
	a := s.allocationFor(src)
	if a == nil || a.expired(time.Now()) {
		return
	}
	peer, err := msg.XorAddress(stun.AttrXorPeerAddress)
	if err != nil {
		return
	}
	dataAttr, ok := msg.Data()
	if !ok || len(dataAttr) == 0 || len(dataAttr) > maxUDPData {
		return
	}
	if !a.hasPermission(peer, time.Now()) {
		return
	}
	_ = a.writeToPeer(dataAttr, peer)
}

// handleChannelData processes a ChannelData frame (RFC 5766 section 2.5).
func (s *Server) handleChannelData(pkt []byte, src *net.UDPAddr) {
	a := s.allocationFor(src)
	if a == nil || a.expired(time.Now()) {
		return
	}
	number, data, err := ParseChannelData(pkt)
	if err != nil || len(data) == 0 || len(data) > maxUDPData {
		return
	}
	cb, ok := a.channelByNumber(number, time.Now())
	if !ok {
		return
	}
	// An active channel carries an implicit permission for its peer.
	_ = a.writeToPeer(data, cb.peer)
}

func (s *Server) allocationFor(src *net.UDPAddr) *Allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocations[s.clientKey(src)]
}
