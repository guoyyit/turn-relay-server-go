package turn

import (
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// createAllocation binds a fresh relay socket on loopback and starts the
// per-allocation relay reader and client writer goroutines.
func (s *Server) createAllocation(client *net.UDPAddr, username string) (*Allocation, error) {
	host, _, err := net.SplitHostPort(s.config.RelayAddress)
	if err != nil {
		return nil, err
	}
	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return nil, newTurnError(CodeInsufficientCapacity, "Insufficient Capacity")
	}
	a := &Allocation{
		client:      client,
		relayConn:   relayConn,
		relayAddr:   relayConn.LocalAddr().(*net.UDPAddr),
		username:    username,
		permissions: make(map[string]*permission),
		channels:    make(map[uint16]*channelBinding),
		peerToChan:  make(map[string]*peerRecord),
		queue:       make(chan pendingItem, s.config.SendQueueSize),
		stop:        make(chan struct{}),
	}
	go serveRelay(a, s)
	go deliverClient(a, s)
	return a, nil
}

// serveRelay reads datagrams arriving from peers on the relay socket.
func serveRelay(a *Allocation, s *Server) {
	buf := make([]byte, 64*1024)
	for {
		n, peer, err := a.relayConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !a.hasPermission(peer.IP, time.Now()) {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		channel, bound := a.channelForPeer(peer.IP)
		item := pendingItem{
			data:       data,
			peer:       peer,
			channel:    channel,
			viaChannel: bound,
		}
		// Bounded non-blocking enqueue: a slow TURN client causes its own
		// datagrams to be dropped, never blocking peers or other clients.
		a.enqueue(item)
	}
}

// deliverClient serializes all writes toward one TURN client, preserving
// per-channel ordering.
func deliverClient(a *Allocation, s *Server) {
	for {
		select {
		case <-a.stop:
			return
		case item := <-a.queue:
			var raw []byte
			var err error
			if item.viaChannel {
				raw, err = stun.MarshalChannelData(item.channel, item.data)
				if err != nil {
					continue
				}
			} else {
				msg := &stun.Message{
					Method: stun.MethodData,
					Class:  stun.ClassIndication,
				}
				peerEnc, encErr := stun.EncodeXorAddress(item.peer.IP, item.peer.Port, msg.TransactionID)
				if encErr != nil {
					continue
				}
				msg.Attributes = []stun.Attribute{
					{Type: stun.AttrXorPeerAddress, Data: peerEnc},
					{Type: stun.AttrData, Data: item.data},
				}
				raw, err = msg.Marshal()
			}
			if err != nil {
				continue
			}
			_ = s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := s.conn.WriteToUDP(raw, a.client); err != nil {
				_ = s.conn.SetWriteDeadline(time.Time{})
				continue
			}
			_ = s.conn.SetWriteDeadline(time.Time{})
		}
	}
}

// sendToPeer forwards one client payload through the relay socket.
func sendToPeer(a *Allocation, peer *net.UDPAddr, data []byte) {
	_ = a.relayConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = a.relayConn.WriteToUDP(data, peer)
	_ = a.relayConn.SetWriteDeadline(time.Time{})
}

// handleChannelData routes a ChannelData message by channel number.
func (s *Server) handleChannelData(raw []byte, src *net.UDPAddr) {
	alloc, ok := s.allocationFor(src)
	if !ok {
		return
	}
	number, data, err := stun.ParseChannelData(raw)
	if err != nil {
		return
	}
	alloc.mu.Lock()
	cb, bound := alloc.channels[number]
	alloc.mu.Unlock()
	if !bound || !time.Now().Before(cb.expiresAt) {
		return
	}
	payload := make([]byte, len(data))
	copy(payload, data)
	// The bound channel implies a matching permission; recheck its liveness.
	if !alloc.hasPermission(cb.peer.IP, time.Now()) {
		return
	}
	go sendToPeer(alloc, cb.peer, payload)
}
