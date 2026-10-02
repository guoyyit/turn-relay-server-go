package turn

import (
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

func authAttrs(realm, nonce string, extra ...stun.Attribute) []stun.Attribute {
	attrs := []stun.Attribute{
		{Type: stun.AttrUsername, Data: []byte("user")},
		{Type: stun.AttrRealm, Data: []byte(realm)},
		{Type: stun.AttrNonce, Data: []byte(nonce)},
	}
	return append(attrs, extra...)
}

func TestRefreshRenewsLifetime(t *testing.T) {
	cfg := Config{DefaultLifetime: 2 * time.Second, MaxLifetime: 10 * time.Second}
	srv, server := startTestServer(t, cfg)
	c := dialClient(t)
	_, key, _, nonce := mustAllocate(t, c, server)

	resp := doRequest(t, c, server, stun.MethodRefresh,
		authAttrs("turn.local", nonce,
			stun.Attribute{Type: stun.AttrLifetime, Data: lifetimeSeconds(5 * time.Second)}), key)
	if resp.Class != stun.ClassSuccessResp {
		t.Fatal("refresh failed")
	}

	time.Sleep(2500 * time.Millisecond)
	if _, ok := allocationForTest(srv, c); !ok {
		t.Fatal("allocation expired despite refresh to 5s")
	}
}

func TestAllocationExpires(t *testing.T) {
	cfg := Config{DefaultLifetime: 1200 * time.Millisecond, MaxLifetime: 5 * time.Second}
	srv, server := startTestServer(t, cfg)
	c := dialClient(t)
	mustAllocate(t, c, server)

	time.Sleep(700 * time.Millisecond)
	if _, ok := allocationForTest(srv, c); !ok {
		t.Fatal("allocation expired too early")
	}
	time.Sleep(1500 * time.Millisecond)
	if _, ok := allocationForTest(srv, c); ok {
		t.Fatal("allocation was not reaped after expiry")
	}
}

func TestRefreshZeroDeletes(t *testing.T) {
	srv, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, _, nonce := mustAllocate(t, c, server)

	resp := doRequest(t, c, server, stun.MethodRefresh,
		authAttrs("turn.local", nonce,
			stun.Attribute{Type: stun.AttrLifetime, Data: lifetimeSeconds(0)}), key)
	if resp.Class != stun.ClassSuccessResp {
		t.Fatal("refresh lifetime=0 failed")
	}
	if _, ok := allocationForTest(srv, c); ok {
		t.Fatal("allocation not deleted by refresh lifetime=0")
	}
}

func TestStaleNonceRejected(t *testing.T) {
	cfg := Config{NonceLifetime: 300 * time.Millisecond}
	_, server := startTestServer(t, cfg)
	c := dialClient(t)

	tx := nextTx()
	first := &stun.Message{
		Method: stun.MethodAllocate, Class: stun.ClassRequest, TransactionID: tx,
		Attributes: []stun.Attribute{
			{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
		},
	}
	raw, _ := first.Marshal()
	challenge := roundTrip(t, c, server, raw)
	realmVal, _ := attrValue(challenge, stun.AttrRealm)
	nonceVal, _ := attrValue(challenge, stun.AttrNonce)

	time.Sleep(400 * time.Millisecond)

	key := stun.LongTermKey("user", string(realmVal), "pass")
	resp := doRequest(t, c, server, stun.MethodAllocate,
		authAttrs(string(realmVal), string(nonceVal),
			stun.Attribute{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}}), key)
	if resp.Class != stun.ClassErrorResp {
		t.Fatal("expected error response with stale nonce")
	}
	code, _ := errorCode(resp)
	if code != CodeStaleNonce {
		t.Fatalf("expected 438 stale nonce, got %d", code)
	}
	newNonce, ok := attrValue(resp, stun.AttrNonce)
	if !ok || string(newNonce) == string(nonceVal) {
		t.Fatal("stale nonce response must carry a fresh nonce")
	}
}
