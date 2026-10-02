package turn

import (
	"net"
	"sync"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// permission represents an authorized peer address.
type permission struct {
	peer      net.IP
	expiresAt time.Time
}

// channelBinding maps a channel number to a peer.
type channelBinding struct {
	number    uint16
	peer      *net.UDPAddr
	expiresAt time.Time
}

// peerRecord is the reverse map from peer address to channel.
type peerRecord struct {
	channel uint16
	bound   bool
}

// pendingItem is a datagram waiting to be delivered to the TURN client.
type pendingItem struct {
	data       []byte
	peer       *net.UDPAddr
	channel    uint16
	viaChannel bool
}

// Allocation is a single client's relay allocation.
type Allocation struct {
	mu        sync.Mutex
	client    *net.UDPAddr
	relayConn *net.UDPConn
	relayAddr *net.UDPAddr
	username  string
	expiresAt time.Time

	permissions map[string]*permission
	channels    map[uint16]*channelBinding
	peerToChan  map[string]*peerRecord

	queue chan pendingItem
	stop  chan struct{}
}

// active reports whether the allocation is still alive.
func (a *Allocation) active(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return now.Before(a.expiresAt)
}

// refreshPermission installs or renews a permission for a peer.
func (a *Allocation) refreshPermission(peer net.IP, now time.Time, lifetime time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.permissions[peer.String()] = &permission{
		peer:      append(net.IP(nil), peer...),
		expiresAt: now.Add(lifetime),
	}
}

// hasPermission reports whether a peer is currently authorized.
func (a *Allocation) hasPermission(peer net.IP, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	p, ok := a.permissions[peer.String()]
	return ok && now.Before(p.expiresAt)
}

// bindChannel binds a channel number to a peer address.
func (a *Allocation) bindChannel(number uint16, peer net.IP, port int, now time.Time, lifetime time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if number < stun.MinChannelNumber || number > stun.MaxChannelNumber {
		return newTurnError(CodeBadRequest, "Channel Number out of range")
	}
	if rec, ok := a.peerToChan[peer.String()]; ok && rec.bound && rec.channel != number {
		return newTurnError(CodeBadRequest, "Peer already bound to another channel")
	}
	if cb, ok := a.channels[number]; ok && (!cb.peer.IP.Equal(peer) || cb.peer.Port != port) {
		return newTurnError(CodeBadRequest, "Channel Number already bound to a different peer")
	}
	a.channels[number] = &channelBinding{
		number: number,
		peer: &net.UDPAddr{
			IP:   append(net.IP(nil), peer...),
			Port: port,
		},
		expiresAt: now.Add(lifetime),
	}
	a.peerToChan[peer.String()] = &peerRecord{channel: number, bound: true}
	// Binding a channel also installs/renews the matching permission (RFC 5766 9).
	a.permissions[peer.String()] = &permission{
		peer:      append(net.IP(nil), peer...),
		expiresAt: now.Add(lifetime),
	}
	return nil
}

// channelForPeer returns the bound channel for a peer.
func (a *Allocation) channelForPeer(peer net.IP) (uint16, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rec, ok := a.peerToChan[peer.String()]; ok && rec.bound {
		return rec.channel, true
	}
	return 0, false
}

// enqueue queues an outbound datagram for the client; drops if full.
func (a *Allocation) enqueue(item pendingItem) bool {
	select {
	case a.queue <- item:
		return true
	default:
		return false
	}
}

// cleanup removes expired permissions and channels.
func (a *Allocation) cleanup(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
}

// cleanupLocked performs cleanup while the caller holds a.mu.
func (a *Allocation) cleanupLocked(now time.Time) {
	for key, p := range a.permissions {
		if !now.Before(p.expiresAt) {
			delete(a.permissions, key)
		}
	}
	for num, cb := range a.channels {
		if !now.Before(cb.expiresAt) {
			delete(a.channels, num)
			if rec, ok := a.peerToChan[cb.peer.IP.String()]; ok && rec.channel == num {
				delete(a.peerToChan, cb.peer.IP.String())
			}
		}
	}
}

// close releases the relay socket and stops goroutines.
func (a *Allocation) close() {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
	if a.relayConn != nil {
		_ = a.relayConn.Close()
	}
}

// setExpiry updates the allocation expiry.
func (a *Allocation) setExpiry(t time.Time) {
	a.mu.Lock()
	a.expiresAt = t
	a.mu.Unlock()
}

// expiry returns the current allocation expiry.
func (a *Allocation) expiry() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.expiresAt
}
