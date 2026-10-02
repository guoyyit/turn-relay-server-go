package turn

import (
	"net"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// testClient is a minimal STUN/TURN client over one UDP socket.
type testClient struct {
	t      *testing.T
	conn   *net.UDPConn
	srv    *net.UDPAddr
	user   string
	passwd string
	realm  string
	key    []byte
}

func newTestClient(t *testing.T, serverAddr, user, password string) *testClient {
	t.Helper()
	srv, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &testClient{
		t:      t,
		conn:   conn,
		srv:    srv,
		user:   user,
		passwd: password,
		realm:  "turn.local",
	}
	if password != "" {
		c.key = LongTermKey(user, c.realm, password)
	}
	return c
}

func (c *testClient) send(m *stun.Message) {
	b, err := m.Marshal()
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.conn.WriteToUDP(b, c.srv); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) recv(timeout time.Duration) (*stun.Message, *net.UDPAddr) {
	buf := make([]byte, 65535)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	m, err := stun.Parse(buf[:n])
	if err != nil {
		c.t.Fatalf("parse response: %v", err)
	}
	return m, addr
}

// recvStun returns the next STUN message that is not an indication (i.e. a
// success/error response), draining interleaved Data indications.
func (c *testClient) recvStun(timeout time.Duration) *stun.Message {
	deadline := time.Now().Add(timeout)
	for {
		_ = c.conn.SetReadDeadline(deadline)
		buf := make([]byte, 65535)
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.t.Fatalf("recvStun: %v", err)
		}
		m, err := stun.Parse(buf[:n])
		if err == nil && m.Class() != stun.ClassIndication {
			return m
		}
	}
}

func (c *testClient) recvRaw(timeout time.Duration) ([]byte, *net.UDPAddr) {
	buf := make([]byte, 65535)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	return buf[:n], addr
}

func (c *testClient) authMsg(method uint16, nonce string) *stun.Message {
	m := stun.New(method, stun.ClassRequest, stunTxID())
	m.AddString(stun.AttrUsername, c.user)
	m.AddString(stun.AttrRealm, c.realm)
	m.AddString(stun.AttrNonce, nonce)
	return m
}

func stunTxID() []byte {
	b := make([]byte, 12)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// doChallenge performs an unauthenticated request and extracts the 401
// challenge material.
func (c *testClient) doChallenge(method uint16) (nonce, realm string) {
	req := stun.New(method, stun.ClassRequest, stunTxID())
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassError {
		c.t.Fatalf("expected error, got class %x", resp.Class())
	}
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusUnauthenticated {
		c.t.Fatalf("code = %d, want 401", code)
	}
	nonce, _ = resp.String(stun.AttrNonce)
	realm, _ = resp.String(stun.AttrRealm)
	if nonce == "" || realm == "" {
		c.t.Fatal("challenge missing nonce/realm")
	}
	return nonce, realm
}

// allocate performs the full long-term credential Allocate exchange.
func (c *testClient) allocate() *net.UDPAddr {
	nonce, realm := c.doChallenge(stun.MethodAllocate)
	c.realm = realm
	c.key = LongTermKey(c.user, realm, c.passwd)

	req := c.authMsg(stun.MethodAllocate, nonce)
	req.AddUint32(stun.AttrRequestedTransport, uint32(udpProto)<<24)
	req.AddIntegrity(c.key)
	req.AddFingerprint()
	c.send(req)

	resp := c.recvStun(2 * time.Second)
	if resp.Class() != stun.ClassSuccess {
		code, reason, _ := resp.ErrorCode()
		c.t.Fatalf("allocate failed: %d %s", code, reason)
	}
	relay, err := resp.XorAddress(stun.AttrXorRelayedAddress)
	if err != nil {
		c.t.Fatal(err)
	}
	mapped, err := resp.XorAddress(stun.AttrXorMappedAddress)
	if err != nil {
		c.t.Fatal(err)
	}
	if mapped.String() != c.conn.LocalAddr().String() {
		c.t.Fatalf("mapped = %s, want %s", mapped, c.conn.LocalAddr())
	}
	return relay
}

func startTestServer(t *testing.T, creds StaticCredentials) (*Server, string) {
	t.Helper()
	srv := New(Config{
		ListenAddr:      "127.0.0.1:0",
		Realm:           "turn.local",
		PublicIP:        "127.0.0.1",
		DefaultLifetime: 5 * time.Second,
		MaxLifetime:     30 * time.Second,
		PermissionTTL:   5 * time.Second,
		ChannelTTL:      10 * time.Second,
		NonceTTL:        150 * time.Millisecond,
		Credentials:     creds,
	})
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	go func() { _ = srv.Serve(conn) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, addr
}

func startTTLServer(t *testing.T, defaultLifetime, permissionTTL,
	channelTTL time.Duration) (*Server, string) {
	t.Helper()
	srv := New(Config{
		ListenAddr:      "127.0.0.1:0",
		Realm:           "turn.local",
		PublicIP:        "127.0.0.1",
		DefaultLifetime: defaultLifetime,
		MaxLifetime:     30 * time.Second,
		PermissionTTL:   permissionTTL,
		ChannelTTL:      channelTTL,
		NonceTTL:        150 * time.Millisecond,
		Credentials:     testCreds(),
	})
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	go func() { _ = srv.Serve(conn) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, addr
}

func startShortTTLServer(t *testing.T) (*Server, string) {
	return startTTLServer(t, 5*time.Second, 200*time.Millisecond, 400*time.Millisecond)
}
