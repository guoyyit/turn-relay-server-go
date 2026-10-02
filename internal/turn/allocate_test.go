package turn

import (
	"testing"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

func TestAllocateRequiresAuthThenSucceeds(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)

	resp, _, _, _ := doChallenge(t, c, server, stun.MethodAllocate, []stun.Attribute{
		{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
	})
	if resp.Class != stun.ClassSuccessResp {
		code, reason := errorCode(resp)
		t.Fatalf("expected success after retry, got %d %s", code, reason)
	}

	if lv, ok := attrValue(resp, stun.AttrLifetime); !ok {
		t.Fatal("missing LIFETIME")
	} else if secs, valid := stun.Uint32Attr(lv); !valid || secs == 0 {
		t.Fatalf("bad lifetime: %x", lv)
	}
	if _, ok := attrValue(resp, stun.AttrXorRelayedAddress); !ok {
		t.Fatal("missing RELAYED-ADDRESS")
	}
	if _, ok := attrValue(resp, stun.AttrXorMappedAddress); !ok {
		t.Fatal("missing XOR-MAPPED-ADDRESS")
	}
}

func TestAllocateUnauthorizedHasChallenge(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)

	req := &stun.Message{
		Method: stun.MethodAllocate, Class: stun.ClassRequest,
		TransactionID: nextTx(),
		Attributes: []stun.Attribute{
			{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
		},
	}
	raw, _ := req.Marshal()
	resp := roundTrip(t, c, server, raw)
	if resp.Class != stun.ClassErrorResp {
		t.Fatal("expected error response")
	}
	code, _ := errorCode(resp)
	if code != CodeUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if _, ok := attrValue(resp, stun.AttrRealm); !ok {
		t.Fatal("401 missing REALM")
	}
	if _, ok := attrValue(resp, stun.AttrNonce); !ok {
		t.Fatal("401 missing NONCE")
	}
}

func TestAllocateConflict(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	mustAllocate(t, c, server)

	resp, _, _, _ := doChallenge(t, c, server, stun.MethodAllocate, []stun.Attribute{
		{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
	})
	code, _ := errorCode(resp)
	if code != CodeAllocMismatch {
		t.Fatalf("expected 437, got %d", code)
	}
}

func TestAllocateUnsupportedTransport(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)

	resp, _, _, _ := doChallenge(t, c, server, stun.MethodAllocate, []stun.Attribute{
		{Type: stun.AttrRequestedTransport, Data: []byte{6, 0, 0, 0}},
	})
	code, _ := errorCode(resp)
	if code != CodeUnsupportedTransport {
		t.Fatalf("expected 442, got %d", code)
	}
}

func TestAllocateWrongPassword(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)

	req := &stun.Message{
		Method: stun.MethodAllocate, Class: stun.ClassRequest,
		TransactionID: nextTx(),
		Attributes: []stun.Attribute{
			{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
		},
	}
	raw, _ := req.Marshal()
	resp := roundTrip(t, c, server, raw)
	realmVal, _ := attrValue(resp, stun.AttrRealm)
	nonceVal, _ := attrValue(resp, stun.AttrNonce)

	badKey := stun.LongTermKey("user", string(realmVal), "wrong-password")
	retry := &stun.Message{
		Method: stun.MethodAllocate, Class: stun.ClassRequest,
		TransactionID: nextTx(),
		Attributes: []stun.Attribute{
			{Type: stun.AttrUsername, Data: []byte("user")},
			{Type: stun.AttrRealm, Data: realmVal},
			{Type: stun.AttrNonce, Data: nonceVal},
			{Type: stun.AttrRequestedTransport, Data: []byte{17, 0, 0, 0}},
		},
	}
	badRaw, _ := retry.MarshalWithIntegrity(badKey)
	resp2 := roundTrip(t, c, server, badRaw)
	if resp2.Class != stun.ClassErrorResp {
		t.Fatal("expected error response for bad credentials")
	}
}

func TestMalformedDatagramIgnored(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	if _, err := c.WriteToUDP([]byte{0x00, 0x01, 0x00, 0x00}, server); err != nil {
		t.Fatal(err)
	}
	// Server stays responsive.
	req := &stun.Message{Method: stun.MethodBinding, Class: stun.ClassRequest, TransactionID: nextTx()}
	raw, _ := req.Marshal()
	resp := roundTrip(t, c, server, raw)
	if resp.Class != stun.ClassSuccessResp {
		t.Fatal("server not responsive after malformed datagram")
	}
}
