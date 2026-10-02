package turn

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	// permissionTTL is the default lifetime of a permission (RFC 5766: 300s).
	permissionTTL = 5 * time.Minute
	// channelTTL is the minimum lifetime of a channel binding (RFC 5766: 600s).
	channelTTL            = 10 * time.Minute
	defaultEgressQueueLen = 256

	// MinChannelNumber / MaxChannelNumber bound TURN channel numbers.
	MinChannelNumber uint16 = 0x4000
	MaxChannelNumber uint16 = 0x4FFF
)

// Errors returned by channel binding; the server maps them to error codes.
var (
	ErrChannelNumberRange = errors.New("turn: channel number outside 0x4000-0x4FFF")
	ErrChannelNumberBusy  = errors.New("turn: channel number already bound to another peer")
	ErrPeerChannelBusy    = errors.New("turn: peer already bound to another channel")
)

// Permission authorises traffic with one peer address (RFC 5766 section 9).
type Permission struct {
	peer      *net.UDPAddr
	expiresAt time.Time
}

// ChannelBinding binds a channel number to a peer (RFC 5766 section 11).
type ChannelBinding struct {
	number    uint16
	peer      *net.UDPAddr
	expiresAt time.Time
}

// Allocation is a single client's relay allocation (its 5-tuple state).
type Allocation struct {
	client   *net.UDPAddr
	relay    *net.UDPConn
	username string

	mu           sync.Mutex
	perms        map[string]*Permission
	channels     map[uint16]*ChannelBinding
	peerChannels map[string]*ChannelBinding
	expiresAt    time.Time

	egress    *egressQueue
	stop      chan struct{}
	closeOnce sync.Once
	closed    bool
	now       func() time.Time
}

func newAllocation(client *net.UDPAddr, relay *net.UDPConn, username string,
	now time.Time, lifetime time.Duration, egressDepth int) *Allocation {
	clock := time.Now
	a := &Allocation{
		client:       client,
		relay:        relay,
		username:     username,
		perms:        make(map[string]*Permission),
		channels:     make(map[uint16]*ChannelBinding),
		peerChannels: make(map[string]*ChannelBinding),
		expiresAt:    now.Add(lifetime),
		egress:       newEgressQueue(egressDepth),
		stop:         make(chan struct{}),
		now:          clock,
	}
	return a
}

func (a *Allocation) expired(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !now.Before(a.expiresAt)
}

// refresh extends (or, with a zero lifetime, ends) the allocation.
func (a *Allocation) refresh(now time.Time, lifetime time.Duration) {
	a.mu.Lock()
	a.expiresAt = now.Add(lifetime)
	a.mu.Unlock()
}

// ensurePermission installs or renews the permission for peer. Binding a
// channel also refreshes the matching permission (RFC 5766 section 9).
func (a *Allocation) ensurePermission(peer *net.UDPAddr, now time.Time, ttl time.Duration) {
	key := peerKey(peer)
	a.mu.Lock()
	if p, ok := a.perms[key]; ok {
		p.expiresAt = now.Add(ttl)
	} else {
		a.perms[key] = &Permission{peer: cloneAddr(peer), expiresAt: now.Add(ttl)}
	}
	a.mu.Unlock()
}

func (a *Allocation) hasPermission(peer *net.UDPAddr, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hasPermissionLocked(peer, now)
}

func (a *Allocation) hasPermissionLocked(peer *net.UDPAddr, now time.Time) bool {
	p, ok := a.perms[peerKey(peer)]
	return ok && now.Before(p.expiresAt)
}

// bindChannel binds number to peer, renewing both the channel and its
// implicit permission. Distinguishable errors are returned for conflicts.
func (a *Allocation) bindChannel(number uint16, peer *net.UDPAddr,
	now time.Time, ttl time.Duration) error {
	if number < MinChannelNumber || number > MaxChannelNumber {
		return ErrChannelNumberRange
	}
	key := peerKey(peer)
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.channels[number]; ok && peerKey(existing.peer) != key {
		return ErrChannelNumberBusy
	}
	if existing, ok := a.peerChannels[key]; ok && existing.number != number {
		return ErrPeerChannelBusy
	}
	cb := a.channels[number]
	if cb == nil {
		cb = &ChannelBinding{number: number, peer: cloneAddr(peer)}
		a.channels[number] = cb
		a.peerChannels[key] = cb
	}
	cb.expiresAt = now.Add(ttl)
	if p, ok := a.perms[key]; ok {
		p.expiresAt = cb.expiresAt
	} else {
		a.perms[key] = &Permission{peer: cloneAddr(peer), expiresAt: cb.expiresAt}
	}
	return nil
}

func (a *Allocation) channelByNumber(number uint16, now time.Time) (*ChannelBinding, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cb, ok := a.channels[number]
	return cb, ok && now.Before(cb.expiresAt)
}

func (a *Allocation) peerChannelLocked(peer *net.UDPAddr, now time.Time) (*ChannelBinding, bool) {
	cb, ok := a.peerChannels[peerKey(peer)]
	return cb, ok && now.Before(cb.expiresAt)
}

// cleanupLocked drops expired permissions and channel bindings.
func (a *Allocation) cleanupLocked(now time.Time) {
	for key, p := range a.perms {
		if !now.Before(p.expiresAt) {
			delete(a.perms, key)
		}
	}
	for number, cb := range a.channels {
		if !now.Before(cb.expiresAt) {
			delete(a.channels, number)
			delete(a.peerChannels, peerKey(cb.peer))
		}
	}
}

// close releases the relay socket and signals background goroutines.
func (a *Allocation) close() error {
	var err error
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		close(a.stop)
		err = a.relay.Close()
	})
	return err
}

func (a *Allocation) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func peerKey(addr *net.UDPAddr) string {
	return addr.String()
}

func cloneAddr(addr *net.UDPAddr) *net.UDPAddr {
	ip := make(net.IP, len(addr.IP))
	copy(ip, addr.IP)
	return &net.UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
}
