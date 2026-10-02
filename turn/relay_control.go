package turn

import (
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// advertisedRelayIP returns the IP announced in XOR-RELAY-ADDRESS.
func (s *Server) advertisedRelayIP(boundIP net.IP) net.IP {
	if s.cfg.PublicIP != "" {
		if ip := net.ParseIP(s.cfg.PublicIP); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4
			}
			return ip
		}
	}
	if ip4 := boundIP.To4(); ip4 != nil {
		return ip4
	}
	return boundIP
}

// relayAddress returns the relay address advertised to the client.
func (s *Server) relayAddress(a *Allocation) *net.UDPAddr {
	local := a.relay.LocalAddr().(*net.UDPAddr)
	return &net.UDPAddr{IP: s.advertisedRelayIP(local.IP), Port: local.Port}
}

// createAllocation binds a new relay UDP socket and starts its goroutines.
func (s *Server) createAllocation(src *net.UDPAddr,
	now time.Time, lifetime time.Duration) (*Allocation, error) {
	host := "0.0.0.0"
	if src.IP.To4() != nil && src.IP.IsLoopback() {
		host = "127.0.0.1"
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host), Port: 0})
	if err != nil {
		return nil, err
	}

	a := newAllocation(src, conn, "", now, lifetime, s.cfg.EgressQueueLen)
	go a.runRelayReceiver()
	go s.runEgressPump(a)
	return a, nil
}

// installAllocation registers a new allocation keyed by client address.
func (s *Server) installAllocation(src *net.UDPAddr, a *Allocation) {
	key := s.clientKey(src)
	s.mu.Lock()
	if existing, ok := s.allocations[key]; ok {
		_ = existing.close()
	}
	s.allocations[key] = a
	s.mu.Unlock()
}

func (s *Server) removeAllocation(src *net.UDPAddr) {
	key := s.clientKey(src)
	s.mu.Lock()
	if _, ok := s.allocations[key]; ok {
		delete(s.allocations, key)
	}
	s.mu.Unlock()
}

// runEgressPump is the single goroutine that sends peer traffic back to a
// client, so ChannelData/Data frames for one allocation stay ordered.
func (s *Server) runEgressPump(a *Allocation) {
	for {
		select {
		case msg := <-a.egress.ch:
			s.deliverPeerMessage(a, msg)
		case <-a.stop:
			return
		}
	}
}

func (s *Server) deliverPeerMessage(a *Allocation, msg *peerMessage) {
	now := time.Now()
	a.mu.Lock()
	cb, bound := a.peerChannelLocked(msg.peer, now)
	a.mu.Unlock()

	var frame []byte
	if bound {
		frame = MarshalChannelData(cb.number, msg.data)
	} else {
		ind := stun.New(methodData, stun.ClassIndication, newTxID())
		ind.AddXorAddress(stun.AttrXorPeerAddress, msg.peer)
		ind.Add(stun.AttrData, msg.data)
		b, err := ind.Marshal()
		if err != nil {
			return
		}
		frame = b
	}
	_, _ = s.conn.WriteToUDP(frame, a.client)
}
