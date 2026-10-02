package turn

import (
	"net"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

func TestCreatePermissionMissingPeer(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	nonce, _ := c.doChallenge(stun.MethodCreatePermission)
	req := c.authMsg(stun.MethodCreatePermission, nonce)
	req.AddIntegrity(c.key)
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
}

func TestChannelBindRequiresAuth(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	// Without credentials: must be challenged even though an allocation exists.
	req := stun.New(stun.MethodChannelBind, stun.ClassRequest, stunTxID())
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusUnauthenticated {
		t.Fatalf("code = %d, want 401", code)
	}
}

func TestChannelBindMissingChannelNumber(t *testing.T) {
	_, addr := startTestServer(t, testCreds())
	c := newTestClient(t, addr, "alice", "pencil")
	c.allocate()

	nonce, _ := c.doChallenge(stun.MethodChannelBind)
	req := c.authMsg(stun.MethodChannelBind, nonce)
	req.AddXorAddress(stun.AttrXorPeerAddress,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001})
	req.AddIntegrity(c.key)
	c.send(req)
	resp := c.recvStun(2 * time.Second)
	code, _, _ := resp.ErrorCode()
	if code != stun.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
}
