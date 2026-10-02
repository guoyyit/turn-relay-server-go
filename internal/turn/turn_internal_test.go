package turn

import (
	"net"
	"testing"
	"time"
)

func TestEnqueueBounded(t *testing.T) {
	a := &Allocation{
		queue: make(chan pendingItem, 2),
		stop:  make(chan struct{}),
	}
	for i := 0; i < 2; i++ {
		if !a.enqueue(pendingItem{data: []byte{byte(i)}}) {
			t.Fatalf("enqueue %d should succeed", i)
		}
	}
	if a.enqueue(pendingItem{data: []byte{9}}) {
		t.Fatal("enqueue must fail when queue is full, never block")
	}
}

func TestPermissionAndChannelExpiry(t *testing.T) {
	now := time.Now()
	a := &Allocation{
		permissions: make(map[string]*permission),
		channels:    make(map[uint16]*channelBinding),
		peerToChan:  make(map[string]*peerRecord),
	}
	ip := net.IPv4(127, 0, 0, 1)
	if err := a.bindChannel(0x4000, ip, 9000, now, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !a.hasPermission(ip, now) {
		t.Fatal("permission should exist after channelbind")
	}
	if _, ok := a.channelForPeer(ip); !ok {
		t.Fatal("channel should exist")
	}
	later := now.Add(200 * time.Millisecond)
	if a.hasPermission(ip, later) {
		t.Fatal("permission should have expired")
	}
	a.mu.Lock()
	if _, ok := a.channels[0x4000]; ok {
		t.Fatal("expired channel not removed by cleanup")
	}
	a.mu.Unlock()
}

func TestSlowClientDoesNotBlockOthers(t *testing.T) {
	// A peer flooding a client with a full bounded queue must not stop a
	// second allocation from relaying data.
	_, server := startTestServer(t, Config{SendQueueSize: 4})

	slowConn := dialClient(t)
	_, slowKey, slowRelay, slowNonce := mustAllocate(t, slowConn, server)
	slowPeer, slowPeerAddr := newPeer(t)
	createPermission(t, slowConn, server, slowKey, slowNonce, slowPeerAddr)
	// Do not read from slowConn: the bounded queue fills and drops.
	for i := 0; i < 64; i++ {
		_, _ = slowPeer.WriteToUDP([]byte("flood"), slowRelay)
	}

	fastConn := dialClient(t)
	_, fastKey, fastRelay, fastNonce := mustAllocate(t, fastConn, server)
	fastPeer, fastPeerAddr := newPeer(t)
	createPermission(t, fastConn, server, fastKey, fastNonce, fastPeerAddr)
	sendIndication(t, fastConn, server, fastPeerAddr, []byte("fast"))
	data, from := waitPayload(t, fastPeer, 2*time.Second)
	if string(data) != "fast" || from.Port != fastRelay.Port {
		t.Fatalf("fast client blocked by slow client: %q from %v", data, from)
	}
}
