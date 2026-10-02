package turn

import (
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// TestChannelExpiry verifies that an expired channel no longer accepts
// ChannelData and that traffic then flows as Data indications.
func TestChannelExpiry(t *testing.T) {
	srv, addr := startShortTTLServer(t)
	c := newTestClient(t, addr, "alice", "pencil")
	relay := c.allocate()

	peerAddr, peerConn, _ := startPeer(t)

	nonce, _ := c.doChallenge(stun.MethodChannelBind)
	req := c.authMsg(stun.MethodChannelBind, nonce)
	req.AddChannelNumber(0x4005)
	req.AddXorAddress(stun.AttrXorPeerAddress, peerAddr)
	req.AddIntegrity(c.key)
	c.send(req)
	if resp := c.recvStun(2 * time.Second); resp.Class() != stun.ClassSuccess {
		t.Fatal("channel bind failed")
	}

	// While bound, peer->client is ChannelData.
	if _, err := peerConn.WriteToUDP([]byte("bound"), relay); err != nil {
		t.Fatal(err)
	}
	raw, _ := c.recvRaw(2 * time.Second)
	if !IsChannelData(raw) {
		t.Fatal("expected ChannelData while channel is bound")
	}

	// Channel TTL is 400ms; wait for expiry.
	time.Sleep(500 * time.Millisecond)
	srv.mu.Lock()
	a := srv.allocations[c.conn.LocalAddr().String()]
	if a == nil {
		t.Fatal("allocation gone (channel TTL must not end allocation)")
	}
	a.mu.Lock()
	a.cleanupLocked(time.Now())
	nChannels := len(a.channels)
	a.mu.Unlock()
	srv.mu.Unlock()
	if nChannels != 0 {
		t.Fatalf("expired channel not reaped: %d remain", nChannels)
	}

	// Permission TTL (200ms) also expired: peer traffic is now dropped until
	// a fresh permission is installed.
	if _, err := peerConn.WriteToUDP([]byte("no-perm"), relay); err != nil {
		t.Fatal(err)
	}
	c.createPermission(t, peerAddr)
	if _, err := peerConn.WriteToUDP([]byte("indication-now"), relay); err != nil {
		t.Fatal(err)
	}
	resp, _ := c.recv(2 * time.Second)
	data, ok := resp.Data()
	if !ok || string(data) != "indication-now" {
		t.Fatalf("after channel expiry expected Data indication, got %q ok=%v", data, ok)
	}
}

// TestChannelDataFromUnknownNumber is silently dropped.
func TestChannelDataFromUnknownNumber(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	frame := MarshalChannelData(0x4FFF, []byte("nobody-home"))
	if _, err := c.conn.WriteToUDP(frame, c.srv); err != nil {
		t.Fatal(err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := c.conn.ReadFromUDP(make([]byte, 100)); err == nil {
		t.Fatal("server replied to unbound channel data")
	}
}
