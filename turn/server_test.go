package turn

import (
	"net"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

func testCreds() StaticCredentials {
	return StaticCredentials{"alice": "pencil", "bob": "password"}
}

func TestBinding(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "", "")

	req := stun.New(stun.MethodBinding, stun.ClassRequest, stunTxID())
	c.send(req)
	resp, from := c.recv(2 * time.Second)
	if from.String() != addr {
		t.Fatalf("reply from %s", from)
	}
	if resp.Class() != stun.ClassSuccess {
		t.Fatalf("class = %x", resp.Class())
	}
	mapped, err := resp.XorAddress(stun.AttrXorMappedAddress)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.String() != c.conn.LocalAddr().String() {
		t.Fatalf("mapped = %s", mapped)
	}
	if _, ok := resp.String(stun.AttrSoftware); !ok {
		t.Fatal("missing SOFTWARE")
	}
	if !resp.FingerprintOK() {
		t.Fatal("binding response failed FINGERPRINT check")
	}
}

func TestAllocateRequiresAuthThenSucceeds(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")

	// Unauthenticated request -> 401 with realm/nonce.
	req := stun.New(stun.MethodAllocate, stun.ClassRequest, stunTxID())
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != 401 {
		t.Fatalf("code = %d, want 401", code)
	}
	nonce, _ := resp.String(stun.AttrNonce)
	realm, _ := resp.String(stun.AttrRealm)

	// Retry with long-term credentials -> success.
	c.realm = realm
	c.key = LongTermKey("alice", realm, "pencil")
	req2 := c.authMsg(stun.MethodAllocate, nonce)
	req2.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req2.AddIntegrity(c.key)
	req2.AddFingerprint()
	c.send(req2)
	resp2, _ := c.recv(2 * time.Second)
	if resp2.Class() != stun.ClassSuccess {
		code, reason, _ := resp2.ErrorCode()
		t.Fatalf("allocate = %d %s", code, reason)
	}
	relay, err := resp2.XorAddress(stun.AttrXorRelayedAddress)
	if err != nil || relay.Port == 0 {
		t.Fatalf("relayed address: %v err=%v", relay, err)
	}
	life, ok := resp2.Lifetime(stun.AttrLifetime)
	if !ok || life <= 0 {
		t.Fatalf("lifetime = %v ok=%v", life, ok)
	}
}

func TestWrongCredentials(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "mallory", "nope")
	nonce, realm := c.doChallenge(stun.MethodAllocate)
	c.key = LongTermKey("mallory", realm, "nope")

	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req.AddIntegrity(c.key)
	c.send(req)

	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusWrongCredentials {
		t.Fatalf("code = %d, want 441", code)
	}
}

func TestTamperedIntegrity(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	nonce, realm := c.doChallenge(stun.MethodAllocate)

	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req.AddIntegrity(LongTermKey("alice", realm, "other-password"))
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusWrongCredentials {
		t.Fatalf("code = %d, want 441", code)
	}
}

func TestStaleNonce(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	nonce, _ := c.doChallenge(stun.MethodAllocate)

	time.Sleep(250 * time.Millisecond) // nonce TTL is 150ms

	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req.AddIntegrity(c.key)
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusStaleNonce {
		t.Fatalf("code = %d, want 438", code)
	}

	// The 438 challenge carries a fresh nonce; retrying must succeed.
	fresh, _ := resp.String(stun.AttrNonce)
	if fresh == "" || fresh == nonce {
		t.Fatal("fresh nonce missing")
	}
	req2 := c.authMsg(stun.MethodAllocate, fresh)
	req2.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req2.AddIntegrity(c.key)
	req2.AddFingerprint()
	c.send(req2)
	resp2, _ := c.recv(2 * time.Second)
	if resp2.Class() != stun.ClassSuccess {
		code, reason, _ := resp2.ErrorCode()
		t.Fatalf("retry = %d %s", code, reason)
	}
}

func TestUnsupportedTransport(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c2 := newTestClient(t, addr, "alice", "pencil")
	nonce, _ := c2.doChallenge(stun.MethodAllocate)
	req := c2.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(6)<<24)
	req.AddIntegrity(c2.key)
	c2.send(req)
	resp := c2.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusUnsupportedTransport {
		t.Fatalf("code = %d, want 442", code)
	}
}

func TestAllocateFromDifferentClient(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	relay := c.allocate()
	if relay == nil {
		t.Fatal("no relay")
	}
}

func TestBadRequestMissingTransport(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	nonce, _ := c.doChallenge(stun.MethodAllocate)
	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddIntegrity(c.key)
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
}

func TestRepeatAllocateRefreshesSameRelay(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	first := c.allocate()

	nonce, _ := c.doChallenge(stun.MethodAllocate)
	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req.AddIntegrity(c.key)
	req.AddFingerprint()
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassSuccess {
		code, reason, _ := resp.ErrorCode()
		t.Fatalf("repeat allocate = %d %s", code, reason)
	}
	relay, err := resp.XorAddress(stun.AttrXorRelayedAddress)
	if err != nil {
		t.Fatal(err)
	}
	if relay.String() != first.String() {
		t.Fatalf("relay changed: %s -> %s", first, relay)
	}
}

func TestRefreshAndExpiry(t *testing.T) {
	srv, addr := startTTLServer(t, 200*time.Millisecond, 200*time.Millisecond, 400*time.Millisecond)
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	// Refresh for a long lifetime.
	nonce, _ := c.doChallenge(stun.MethodRefresh)
	req := c.authMsg(stun.MethodRefresh, nonce)
	req.AddLifetime(stun.AttrLifetime, 2*time.Second)
	req.AddIntegrity(c.key)
	req.AddFingerprint()
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassSuccess {
		code, reason, _ := resp.ErrorCode()
		t.Fatalf("refresh = %d %s", code, reason)
	}

	key := c.conn.LocalAddr().String()
	srv.mu.Lock()
	a := srv.allocations[key]
	srv.mu.Unlock()
	if a == nil {
		t.Fatal("allocation missing")
	}
	initialExpiry := func() time.Time {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.expiresAt
	}()

	// Wait past the default 200ms expiry but within the refreshed lifetime.
	time.Sleep(350 * time.Millisecond)
	srv.mu.Lock()
	stillThere := srv.allocations[key] != nil
	srv.mu.Unlock()
	if !stillThere {
		t.Fatal("allocation reaped despite refresh")
	}

	// Refresh with lifetime 0 deletes the allocation immediately.
	nonce2, _ := c.doChallenge(stun.MethodRefresh)
	req2 := c.authMsg(stun.MethodRefresh, nonce2)
	req2.AddUint32(stun.AttrLifetime, 0)
	req2.AddIntegrity(c.key)
	c.send(req2)
	resp2, _ := c.recv(2 * time.Second)
	if resp2.Class() != stun.ClassSuccess {
		t.Fatal("delete refresh failed")
	}
	srv.mu.Lock()
	gone := srv.allocations[key] == nil
	srv.mu.Unlock()
	if !gone {
		t.Fatal("allocation still present after lifetime=0")
	}

	_ = initialExpiry
}

func TestAllocationExpiresAndReaps(t *testing.T) {
	srv, addr := startTTLServer(t, 200*time.Millisecond, 200*time.Millisecond, 400*time.Millisecond)
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()
	key := c.conn.LocalAddr().String()

	srv.reapExpired(time.Now())
	srv.mu.Lock()
	present := srv.allocations[key] != nil
	srv.mu.Unlock()
	if !present {
		t.Fatal("fresh allocation reaped")
	}

	time.Sleep(300 * time.Millisecond) // default lifetime 200ms
	srv.reapExpired(time.Now())
	srv.mu.Lock()
	present = srv.allocations[key] != nil
	srv.mu.Unlock()
	if present {
		t.Fatal("expired allocation not reaped")
	}
}

func TestRequestsWithoutAllocation(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")

	nonce, _ := c.doChallenge(stun.MethodRefresh)
	req := c.authMsg(stun.MethodRefresh, nonce)
	req.AddIntegrity(c.key)
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusAllocMismatch {
		t.Fatalf("code = %d, want 437", code)
	}
}

func TestMalformedDatagramIgnored(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	udpSrv, _ := net.ResolveUDPAddr("udp4", addr)
	conn, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	defer conn.Close()

	_, _ = conn.WriteToUDP([]byte{0xff, 0xff, 0, 0}, udpSrv)
	_, _ = conn.WriteToUDP(make([]byte, 20), udpSrv)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := conn.ReadFromUDP(make([]byte, 100))
	if err == nil {
		t.Fatal("expected no reply for malformed datagrams")
	}
}
