package turn

import (
	"net"
	"testing"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

func TestBindingSuccess(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)

	tx := nextTx()
	req := &stun.Message{
		Method: stun.MethodBinding, Class: stun.ClassRequest, TransactionID: tx,
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	resp := roundTrip(t, c, server, raw)
	if resp.Class != stun.ClassSuccessResp || resp.Method != stun.MethodBinding {
		t.Fatalf("bad response: method=%x class=%x", resp.Method, resp.Class)
	}
	if resp.TransactionID != tx {
		t.Fatal("transaction id mismatch")
	}
	v, ok := attrValue(resp, stun.AttrXorMappedAddress)
	if !ok {
		t.Fatal("missing XOR-MAPPED-ADDRESS")
	}
	ip, port, err := stun.DecodeXorAddress(v, tx)
	if err != nil {
		t.Fatal(err)
	}
	local := c.LocalAddr().(*net.UDPAddr)
	if !ip.Equal(local.IP) || port != local.Port {
		t.Fatalf("mapped address %v:%d != client %v", ip, port, local)
	}
}

func TestBindingWithoutAuth(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	req := &stun.Message{Method: stun.MethodBinding, Class: stun.ClassRequest, TransactionID: nextTx()}
	raw, _ := req.Marshal()
	resp := roundTrip(t, c, server, raw)
	if resp.Class != stun.ClassSuccessResp {
		t.Fatal("binding must not require authentication")
	}
}
