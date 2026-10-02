package turn

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

func startTestServer(t *testing.T, cfg Config) (*Server, *net.UDPAddr) {
	t.Helper()
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.RelayAddress = "127.0.0.1:0"
	if cfg.Realm == "" {
		cfg.Realm = "turn.local"
	}
	if cfg.Credentials == nil {
		cfg.Credentials = map[string]string{"user": "pass"}
	}
	srv := NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	go func() { _ = srv.ListenAndServe(ctx) }()
	select {
	case <-srv.Started:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not start")
	}
	return srv, srv.LocalAddr()
}

func dialClient(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var testTxCounter atomic.Uint32

func nextTx() [12]byte {
	n := testTxCounter.Add(1)
	var tx [12]byte
	tx[0] = byte(n >> 24)
	tx[1] = byte(n >> 16)
	tx[2] = byte(n >> 8)
	tx[3] = byte(n)
	return tx
}

// roundTrip sends one STUN message and returns the parsed response.
func roundTrip(t *testing.T, c *net.UDPConn, server *net.UDPAddr, raw []byte) *stun.Message {
	t.Helper()
	if _, err := c.WriteToUDP(raw, server); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64*1024)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("timeout waiting for response: %v", err)
	}
	msg, err := stun.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse response: %v (raw=%x)", err, buf[:n])
	}
	return msg
}

func readDatagram(t *testing.T, c *net.UDPConn, wait time.Duration) []byte {
	t.Helper()
	buf := make([]byte, 64*1024)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

// request builds an authenticated STUN request after completing the 401
// challenge exchange if needed. It returns the parsed success/error response.
func doRequest(t *testing.T, c *net.UDPConn, server *net.UDPAddr,
	method uint16, attrs []stun.Attribute, key []byte) *stun.Message {
	t.Helper()
	tx := nextTx()
	msg := &stun.Message{
		Method: method, Class: stun.ClassRequest,
		TransactionID: tx, Attributes: attrs,
	}
	raw, err := msg.MarshalWithIntegrity(key)
	if err != nil {
		t.Fatal(err)
	}
	return roundTrip(t, c, server, raw)
}

// doChallenge performs the unauthenticated request, extracts realm/nonce,
// derives the key, and retries with credentials.
func doChallenge(t *testing.T, c *net.UDPConn, server *net.UDPAddr,
	method uint16, attrs []stun.Attribute) (*stun.Message, string, string, []byte) {
	t.Helper()
	tx := nextTx()
	first := &stun.Message{
		Method: method, Class: stun.ClassRequest,
		TransactionID: tx, Attributes: attrs,
	}
	raw, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	resp := roundTrip(t, c, server, raw)
	if resp.Class != stun.ClassErrorResp {
		t.Fatalf("expected error response, got class %x", resp.Class)
	}
	code, _ := errorCode(resp)
	if code != CodeUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	realmVal, _ := attrValue(resp, stun.AttrRealm)
	nonceVal, _ := attrValue(resp, stun.AttrNonce)
	realm := string(realmVal)
	nonce := string(nonceVal)

	authAttrs := append([]stun.Attribute{
		{Type: stun.AttrUsername, Data: []byte("user")},
		{Type: stun.AttrRealm, Data: realmVal},
		{Type: stun.AttrNonce, Data: nonceVal},
	}, attrs...)
	key := stun.LongTermKey("user", realm, "pass")
	resp2 := doRequest(t, c, server, method, authAttrs, key)
	return resp2, realm, nonce, key
}

func errorCode(msg *stun.Message) (int, string) {
	v, ok := attrValue(msg, stun.AttrErrorCode)
	if !ok {
		return 0, ""
	}
	return stun.DecodeErrorCode(v)
}

func allocationForTest(srv *Server, c *net.UDPConn) (*Allocation, bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	a, ok := srv.allocations[c.LocalAddr().String()]
	return a, ok
}

func mustAllocate(t *testing.T, c *net.UDPConn, server *net.UDPAddr) (*stun.Message, []byte, *net.UDPAddr, string) {
	t.Helper()
	attrs := []stun.Attribute{
		{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
	}
	resp, _, nonce, key := doChallenge(t, c, server, stun.MethodAllocate, attrs)
	if resp.Class != stun.ClassSuccessResp {
		code, reason := errorCode(resp)
		t.Fatalf("allocate failed: %d %s", code, reason)
	}
	relayVal, ok := attrValue(resp, stun.AttrXorRelayedAddress)
	if !ok {
		t.Fatal("missing RELAYED-ADDRESS")
	}
	ip, port, err := stun.DecodeXorAddress(relayVal, resp.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	return resp, key, &net.UDPAddr{IP: ip, Port: port}, nonce
}
