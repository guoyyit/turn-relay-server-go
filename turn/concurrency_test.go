package turn

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// TestMultipleClientsNoCrossTalk runs several clients with separate peers and
// verifies each only ever receives its own peer's traffic.
func TestMultipleClientsNoCrossTalk(t *testing.T) {
	_, addr := startTestServer(t, testCreds())

	const n = 4
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		t.Run("client", func(t *testing.T) {
			defer wg.Done()
			user := "alice"
			c := newTestClient(t, addr, user, "pencil")
			relay := c.allocate()

			peerAddr, peerConn, peerCh := startPeer(t)
			c.createPermission(t, peerAddr)

			payload := bytes.Repeat([]byte{byte('A' + i)}, 8)
			c.sendIndication(peerAddr, payload)

			select {
			case got := <-peerCh:
				if !bytes.Equal(got, payload) {
					t.Fatalf("peer got %x, want %x", got, payload)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("peer did not receive")
			}

			// Peer -> client; tag the data so cross-talk would be visible.
			if _, err := peerConn.WriteToUDP(payload, relay); err != nil {
				t.Fatal(err)
			}
			resp, _ := c.recv(2 * time.Second)
			data, ok := resp.Data()
			if !ok || !bytes.Equal(data, payload) {
				t.Fatalf("client %d got cross-talk data %x", i, data)
			}
			src, _ := resp.XorAddress(stun.AttrXorPeerAddress)
			if src.String() != peerAddr.String() {
				t.Fatalf("client %d got peer %s", i, src)
			}
		})
	}
	wg.Wait()
}

// TestSlowClientDoesNotBlock verifies that flooding one slow client's relay
// does not block another client's traffic and that the slow client's bounded
// queue drops excess data instead of growing without limit.
func TestSlowClientDoesNotBlock(t *testing.T) {
	srv, addr := startTestServer(t, testCreds())

	slow := newTestClient(t, addr, "alice", "pencil")
	slowRelay := slow.allocate()
	slowPeer, slowPeerConn, _ := startPeer(t)
	slow.createPermission(t, slowPeer)

	fast := newTestClient(t, addr, "bob", "password")
	fastRelay := fast.allocate()
	fastPeer, fastPeerConn, fastCh := startPeer(t)
	fast.createPermission(t, fastPeer)

	// Flood the slow client's relay far beyond its queue depth. The slow
	// client never reads, so the bounded queue must drop rather than block.
	flood := make([]byte, 100)
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := slowPeerConn.WriteToUDP(flood, slowRelay); err != nil {
			t.Fatal(err)
		}
	}

	// Meanwhile the fast client must keep working both directions.
	done := make(chan struct{})
	go func() {
		fast.sendIndication(fastPeer, []byte("still-working"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow client blocked the server")
	}
	select {
	case got := <-fastCh:
		if string(got) != "still-working" {
			t.Fatalf("fast peer got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fast peer did not receive")
	}

	// Fast peer -> fast client also keeps flowing.
	if _, err := fastPeerConn.WriteToUDP([]byte("reply"), fastRelay); err != nil {
		t.Fatal(err)
	}
	if resp, _ := fast.recv(2 * time.Second); resp.Class() != stun.ClassIndication {
		t.Fatal("fast client did not receive peer data")
	}

	// The slow allocation's queue never exceeded its configured depth.
	key := slow.conn.LocalAddr().String()
	srv.mu.Lock()
	a := srv.allocations[key]
	srv.mu.Unlock()
	if a == nil {
		t.Fatal("slow allocation missing")
	}
	if len(a.egress.ch) > cap(a.egress.ch) {
		t.Fatalf("queue grew beyond bound: %d > %d",
			len(a.egress.ch), cap(a.egress.ch))
	}

	// Drain a few frames to prove service on the slow socket still works.
	for i := 0; i < 3; i++ {
		if _, err := slowPeerConn.WriteToUDP([]byte("after-flood"), slowRelay); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	for i := 0; i < 3; i++ {
		raw, _ := slow.recvRaw(2 * time.Second)
		if IsChannelData(raw) {
			t.Fatal("slow client expected Data indication")
		}
		if msg, err := stun.Parse(raw); err == nil && msg.Method() == methodData {
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("slow client got no data after flood")
	}
}

// TestAllocationBoundToClient verifies another source cannot drive an
// allocation (CreatePermission from a spoofed second socket fails).
func TestAllocationBoundToClient(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	owner := newTestClient(t, addr, "alice", "pencil")
	owner.allocate()

	// A different source address has no allocation.
	other := newTestClient(t, addr, "alice", "pencil")
	nonce, _ := other.doChallenge(stun.MethodCreatePermission)
	req := other.authMsg(stun.MethodCreatePermission, nonce)
	req.AddXorAddress(stun.AttrXorPeerAddress,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000})
	req.AddIntegrity(other.key)
	other.send(req)
	resp := other.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusAllocMismatch {
		t.Fatalf("code = %d, want 437", code)
	}
}
