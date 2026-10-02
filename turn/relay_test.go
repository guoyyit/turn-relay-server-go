package turn

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// startPeer starts a UDP peer; every received datagram is delivered to ch.
// The caller must read from ch (not from conn directly).
func startPeer(t *testing.T) (*net.UDPAddr, *net.UDPConn, chan []byte) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ch := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ch <- pkt
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), conn, ch
}

func (c *testClient) createPermission(t *testing.T, peer *net.UDPAddr) {
	t.Helper()
	nonce, _ := c.doChallenge(stun.MethodCreatePermission)
	req := c.authMsg(stun.MethodCreatePermission, nonce)
	req.AddXorAddress(stun.AttrXorPeerAddress, peer)
	req.AddIntegrity(c.key)
	req.AddFingerprint()
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassSuccess {
		code, reason, _ := resp.ErrorCode()
		t.Fatalf("create permission = %d %s", code, reason)
	}
}

func (c *testClient) sendIndication(peer *net.UDPAddr, data []byte) {
	ind := stun.New(methodSend, stun.ClassIndication, stunTxID())
	ind.AddXorAddress(stun.AttrXorPeerAddress, peer)
	ind.Add(stun.AttrData, data)
	c.send(ind)
}

func TestSendIndicationRequiresPermission(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	relay := c.allocate()

	peerAddr, peerConn, peerCh := startPeer(t)

	// A second, unauthorised peer never appears in the permission list.
	otherAddr, _, otherCh := startPeer(t)
	c.sendIndication(otherAddr, []byte("blocked"))
	select {
	case got := <-peerCh:
		t.Fatalf("peer unexpectedly received %q without permission", got)
	case got := <-otherCh:
		t.Fatalf("unauthorised peer received %q", got)
	default:
	}

	c.createPermission(t, peerAddr)

	// After permission: peer receives via the relay address.
	c.sendIndication(peerAddr, []byte("hello-via-send"))
	var got []byte
	select {
	case got = <-peerCh:
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive data")
	}
	if string(got) != "hello-via-send" {
		t.Fatalf("peer got %q", got)
	}

	// Peer -> relay -> client as Data indication.
	if _, err := peerConn.WriteToUDP([]byte("reply-from-peer"), relay); err != nil {
		t.Fatal(err)
	}
	resp, _ := c.recv(2 * time.Second)
	if resp.Class() != stun.ClassIndication || resp.Method() != methodData {
		t.Fatalf("not a Data indication: %x/%x", resp.Class(), resp.Method())
	}
	src, err := resp.XorAddress(stun.AttrXorPeerAddress)
	if err != nil || src.String() != peerAddr.String() {
		t.Fatalf("peer addr = %v err=%v", src, err)
	}
	data, ok := resp.Data()
	if !ok || string(data) != "reply-from-peer" {
		t.Fatalf("data = %q ok=%v", data, ok)
	}
}

func TestPermissionExpiry(t *testing.T) {
	_, addr := startShortTTLServer(t)
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()
	peerAddr, _, peerCh := startPeer(t)

	c.createPermission(t, peerAddr)
	time.Sleep(350 * time.Millisecond) // permission TTL 200ms

	c.sendIndication(peerAddr, []byte("late"))
	select {
	case got := <-peerCh:
		t.Fatalf("peer received %q after permission expired", got)
	case <-time.After(400 * time.Millisecond):
	}
}

func TestChannelDataForwarding(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	relay := c.allocate()

	peerAddr, peerConn, peerCh := startPeer(t)

	// Bind channel 0x4000 to the peer.
	nonce, _ := c.doChallenge(stun.MethodChannelBind)
	req := c.authMsg(stun.MethodChannelBind, nonce)
	req.AddChannelNumber(0x4000)
	req.AddXorAddress(stun.AttrXorPeerAddress, peerAddr)
	req.AddIntegrity(c.key)
	req.AddFingerprint()
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassSuccess {
		code, reason, _ := resp.ErrorCode()
		t.Fatalf("channel bind = %d %s", code, reason)
	}

	// ChannelData client -> peer; channel bind also installs the permission.
	frame := MarshalChannelData(0x4000, []byte("via-channel"))
	if _, err := c.conn.WriteToUDP(frame, c.srv); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-peerCh:
		if string(got) != "via-channel" {
			t.Fatalf("peer got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive channel data")
	}

	// Peer -> relay -> client must come back as ChannelData on 0x4000.
	if _, err := peerConn.WriteToUDP([]byte("peer-to-channel"), relay); err != nil {
		t.Fatal(err)
	}
	raw, _ := c.recvRaw(2 * time.Second)
	number, data, err := ParseChannelData(raw)
	if err != nil {
		t.Fatalf("expected channel data: %v (%x)", err, raw[:min(4, len(raw))])
	}
	if number != 0x4000 || string(data) != "peer-to-channel" {
		t.Fatalf("number=%x data=%q", number, data)
	}
}

func TestChannelOrdering(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	relay := c.allocate()
	peerAddr, peerConn, _ := startPeer(t)

	nonce, _ := c.doChallenge(stun.MethodChannelBind)
	req := c.authMsg(stun.MethodChannelBind, nonce)
	req.AddChannelNumber(0x4011)
	req.AddXorAddress(stun.AttrXorPeerAddress, peerAddr)
	req.AddIntegrity(c.key)
	c.send(req)
	if resp := c.recvStun(2 * time.Second); resp.Class() != stun.ClassSuccess {
		t.Fatal("channel bind failed")
	}

	const n = 50
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 32)
		if _, err := peerConn.WriteToUDP(payload, relay); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		raw, _ := c.recvRaw(3 * time.Second)
		number, data, err := ParseChannelData(raw)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if number != 0x4011 || !bytes.Equal(data, bytes.Repeat([]byte{byte(i)}, 32)) {
			t.Fatalf("frame %d out of order: number=%x len=%d", i, number, len(data))
		}
	}
}

func TestChannelConflicts(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	peer1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7101}
	peer2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7102}

	bind := func(number uint16, peer *net.UDPAddr) int {
		nonce, _ := c.doChallenge(stun.MethodChannelBind)
		req := c.authMsg(stun.MethodChannelBind, nonce)
		req.AddChannelNumber(number)
		req.AddXorAddress(stun.AttrXorPeerAddress, peer)
		req.AddIntegrity(c.key)
		c.send(req)
		resp := c.recvStun(2 * time.Second)
		code, _, _ := resp.ErrorCode()
		if resp.Class() == stun.ClassSuccess {
			return 0
		}
		return code
	}

	if code := bind(0x5000, peer1); code != stun.StatusBadRequest {
		t.Fatalf("out-of-range code = %d, want 400", code)
	}
	if code := bind(0x4000, peer1); code != 0 {
		t.Fatalf("first bind code = %d", code)
	}
	if code := bind(0x4000, peer2); code != stun.StatusBadRequest {
		t.Fatalf("number conflict code = %d, want 400", code)
	}
	if code := bind(0x4001, peer1); code != stun.StatusBadRequest {
		t.Fatalf("peer conflict code = %d, want 400", code)
	}
	// Rebinding the same number to the same peer is a renewal and succeeds.
	if code := bind(0x4000, peer1); code != 0 {
		t.Fatalf("renewal code = %d, want success", code)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
