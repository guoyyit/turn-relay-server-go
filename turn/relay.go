package turn

import (
	"net"
	"time"
)

// maxUDPData is the largest TURN data payload that fits in a UDP datagram
// after STUN/ChannelDataFraming (RFC 5766 section 2.1/2.5).
const maxUDPData = 65535 - 4 // ChannelData header is the tightest frame

// peerMessage is one datagram received on a relay address from a peer.
type peerMessage struct {
	peer *net.UDPAddr
	data []byte
}

// egressQueue is the bounded per-allocation buffer of peer->client packets.
// A full queue drops the new packet, so a slow client never blocks the relay
// receive loop or other allocations.
type egressQueue struct {
	ch chan *peerMessage
}

func newEgressQueue(depth int) *egressQueue {
	if depth <= 0 {
		depth = defaultEgressQueueLen
	}
	return &egressQueue{ch: make(chan *peerMessage, depth)}
}

// push never blocks; it reports whether the packet was buffered.
func (q *egressQueue) push(msg *peerMessage) bool {
	select {
	case q.ch <- msg:
		return true
	default:
		return false
	}
}

// writeToPeer sends data to peer from the allocation's relay socket.
func (a *Allocation) writeToPeer(data []byte, peer *net.UDPAddr) error {
	_, err := a.relay.WriteToUDP(data, peer)
	return err
}

// runRelayReceiver reads datagrams arriving on the allocation's relay socket.
// Asynchronous ICMP errors caused by unreachable peers are surfaced on the
// socket; they are tolerated so one dead peer cannot stop service for others.
func (a *Allocation) runRelayReceiver() {
	buf := make([]byte, maxUDPData+1)
	for {
		n, addr, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			if a.isClosed() {
				return
			}
			// Consume the transient asynchronous error and keep reading, but
			// avoid a hot loop if the kernel keeps reporting it.
			time.Sleep(time.Millisecond)
			continue
		}
		if n == 0 || n > maxUDPData {
			continue
		}
		peer := *addr
		now := a.now()
		a.mu.Lock()
		allowed := a.hasPermissionLocked(&peer, now)
		a.mu.Unlock()
		if !allowed {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		a.egress.push(&peerMessage{peer: &peer, data: data})
	}
}
