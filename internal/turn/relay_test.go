package turn

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

func newPeer(t *testing.T) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc, pc.LocalAddr().(*net.UDPAddr)
}

func createPermission(t *testing.T, c *net.UDPConn, server *net.UDPAddr, keyBytes []byte, nonce string, peer *net.UDPAddr) {
	t.Helper()
	enc, err := stun.EncodeXorAddress(peer.IP, peer.Port, [12]byte{})
	if err != nil {
		t.Fatal(err)
	}
	resp := doRequest(t, c, server, stun.MethodCreatePerm,
		authAttrs("turn.local", nonce,
			stun.Attribute{Type: stun.AttrXorPeerAddress, Data: enc}), keyBytes)
	if resp.Class != stun.ClassSuccessResp {
		code, reason := errorCode(resp)
		t.Fatalf("createpermission failed: %d %s", code, reason)
	}
}

func sendIndication(t *testing.T, c *net.UDPConn, server, peer *net.UDPAddr, payload []byte) {
	t.Helper()
	tx := nextTx()
	peerEnc, err := stun.EncodeXorAddress(peer.IP, peer.Port, tx)
	if err != nil {
		t.Fatal(err)
	}
	msg := &stun.Message{
		Method: stun.MethodSend, Class: stun.ClassIndication, TransactionID: tx,
		Attributes: []stun.Attribute{
			{Type: stun.AttrXorPeerAddress, Data: peerEnc},
			{Type: stun.AttrData, Data: payload},
		},
	}
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDP(raw, server); err != nil {
		t.Fatal(err)
	}
}

func waitPayload(t *testing.T, pc *net.UDPConn, d time.Duration) ([]byte, *net.UDPAddr) {
	t.Helper()
	buf := make([]byte, 64*1024)
	_ = pc.SetReadDeadline(time.Now().Add(d))
	n, from, err := pc.ReadFromUDP(buf)
	if err != nil {
		return nil, nil
	}
	return append([]byte(nil), buf[:n]...), from
}

func TestSendIndicationRequiresPermission(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, _, relay, _ := mustAllocate(t, c, server)
	peer, peerAddr := newPeer(t)
	_ = relay

	sendIndication(t, c, server, peerAddr, []byte("blocked"))
	if data, _ := waitPayload(t, peer, 300*time.Millisecond); data != nil {
		t.Fatal("peer received data without a permission")
	}
}

func TestSendIndicationRelayedAfterPermission(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, relay, nonce := mustAllocate(t, c, server)
	peer, peerAddr := newPeer(t)

	createPermission(t, c, server, key, nonce, peerAddr)
	sendIndication(t, c, server, peerAddr, []byte("hello peer"))

	data, from := waitPayload(t, peer, 2*time.Second)
	if string(data) != "hello peer" {
		t.Fatalf("peer got %q", data)
	}
	if !from.IP.Equal(relay.IP) || from.Port != relay.Port {
		t.Fatalf("data came from %v, expected relay %v", from, relay)
	}
}

func TestPeerDataIndication(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, relay, nonce := mustAllocate(t, c, server)
	peer, peerAddr := newPeer(t)
	createPermission(t, c, server, key, nonce, peerAddr)

	if _, err := peer.WriteToUDP([]byte("hi client"), relay); err != nil {
		t.Fatal(err)
	}
	raw := readDatagram(t, c, 2*time.Second)
	if raw == nil {
		t.Fatal("client did not receive Data indication")
	}
	msg, err := stun.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Method != stun.MethodData || msg.Class != stun.ClassIndication {
		t.Fatalf("unexpected method=%x class=%x", msg.Method, msg.Class)
	}
	peerEnc, ok := attrValue(msg, stun.AttrXorPeerAddress)
	if !ok {
		t.Fatal("missing XOR-PEER-ADDRESS")
	}
	ip, port, err := stun.DecodeXorAddress(peerEnc, msg.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(peerAddr.IP) || port != peerAddr.Port {
		t.Fatalf("peer address mismatch %v:%d", ip, port)
	}
	d, _ := attrValue(msg, stun.AttrData)
	if string(d) != "hi client" {
		t.Fatalf("data %q", d)
	}
}

func TestCreatePermissionRequiresAuth(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	mustAllocate(t, c, server)
	_, peerAddr := newPeer(t)
	enc, _ := stun.EncodeXorAddress(peerAddr.IP, peerAddr.Port, [12]byte{})
	msg := &stun.Message{
		Method: stun.MethodCreatePerm, Class: stun.ClassRequest, TransactionID: nextTx(),
		Attributes: []stun.Attribute{{Type: stun.AttrXorPeerAddress, Data: enc}},
	}
	raw, _ := msg.Marshal()
	resp := roundTrip(t, c, server, raw)
	code, _ := errorCode(resp)
	if code != CodeUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
}

func TestPermissionExpiryDropsData(t *testing.T) {
	cfg := Config{PermissionLifetime: 500 * time.Millisecond}
	_, server := startTestServer(t, cfg)
	c := dialClient(t)
	_, key, relay, nonce := mustAllocate(t, c, server)
	peer, peerAddr := newPeer(t)
	createPermission(t, c, server, key, nonce, peerAddr)

	time.Sleep(900 * time.Millisecond)

	sendIndication(t, c, server, peerAddr, []byte("late"))
	if data, _ := waitPayload(t, peer, 300*time.Millisecond); data != nil {
		t.Fatal("data relayed after permission expiry")
	}
	if _, err := peer.WriteToUDP([]byte("late"), relay); err != nil {
		t.Fatal(err)
	}
	if raw := readDatagram(t, c, 300*time.Millisecond); raw != nil {
		t.Fatal("client received peer data after permission expiry")
	}
}

func bindChannel(t *testing.T, c *net.UDPConn, server *net.UDPAddr, keyBytes []byte, nonce string, number uint16, peer *net.UDPAddr) *stun.Message {
	t.Helper()
	tx := nextTx()
	enc, err := stun.EncodeXorAddress(peer.IP, peer.Port, tx)
	if err != nil {
		t.Fatal(err)
	}
	return doRequest(t, c, server, stun.MethodChannelBind,
		authAttrs("turn.local", nonce,
			stun.Attribute{Type: stun.AttrChannelNumber, Data: stun.EncodeChannelNumber(number)},
			stun.Attribute{Type: stun.AttrXorPeerAddress, Data: enc}), keyBytes)
}

func TestChannelBindRoundTripAndOrder(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, relay, nonce := mustAllocate(t, c, server)
	peer, peerAddr := newPeer(t)

	resp := bindChannel(t, c, server, key, nonce, 0x4000, peerAddr)
	if resp.Class != stun.ClassSuccessResp {
		code, reason := errorCode(resp)
		t.Fatalf("channelbind failed: %d %s", code, reason)
	}

	// Client -> peer over the channel, in order.
	for i := 0; i < 20; i++ {
		payload := []byte{byte('a' + i%26), byte(i)}
		frame, err := stun.MarshalChannelData(0x4000, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.WriteToUDP(frame, server); err != nil {
			t.Fatal(err)
		}
		data, from := waitPayload(t, peer, 2*time.Second)
		if !bytes.Equal(data, payload) || from.Port != relay.Port {
			t.Fatalf("channel frame %d mismatch: %q from %v", i, data, from)
		}
	}

	// Peer -> client is delivered as ChannelData, routed and ordered.
	for i := 0; i < 20; i++ {
		payload := []byte{byte('A' + i%26), byte(i)}
		if _, err := peer.WriteToUDP(payload, relay); err != nil {
			t.Fatal(err)
		}
		raw := readDatagram(t, c, 2*time.Second)
		if raw == nil {
			t.Fatalf("missing channel frame %d", i)
		}
		ch, data, err := stun.ParseChannelData(raw)
		if err != nil {
			t.Fatal(err)
		}
		if ch != 0x4000 || !bytes.Equal(data, payload) {
			t.Fatalf("frame %d: channel %x data %q", i, ch, data)
		}
	}
}

func TestChannelBindConflict(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, _, nonce := mustAllocate(t, c, server)
	peer1, addr1 := newPeer(t)
	peer2, addr2 := newPeer(t)
	_ = peer1
	_ = peer2

	createPermission(t, c, server, key, nonce, addr1)
	createPermission(t, c, server, key, nonce, addr2)
	if resp := bindChannel(t, c, server, key, nonce, 0x4000, addr1); resp.Class != stun.ClassSuccessResp {
		t.Fatal("first channelbind failed")
	}
	resp := bindChannel(t, c, server, key, nonce, 0x4000, addr2)
	if resp.Class != stun.ClassErrorResp {
		t.Fatal("expected channel conflict error")
	}
	code, _ := errorCode(resp)
	if code != CodeBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestChannelNumberOutOfRange(t *testing.T) {
	_, server := startTestServer(t, Config{})
	c := dialClient(t)
	_, key, _, nonce := mustAllocate(t, c, server)
	_, peerAddr := newPeer(t)
	resp := bindChannel(t, c, server, key, nonce, 0x1000, peerAddr)
	code, _ := errorCode(resp)
	if code != CodeBadRequest {
		t.Fatalf("expected 400 for out-of-range channel, got %d", code)
	}
}

func TestConcurrentClientsIsolation(t *testing.T) {
	_, server := startTestServer(t, Config{})
	const n = 8
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()

			_, key, relay, nonce := mustAllocate(t, c, server)
			peer, peerAddr := newPeer(t)
			createPermission(t, c, server, key, nonce, peerAddr)
			payload := []byte("client-")
			payload = append(payload, byte('0'+i))
			sendIndication(t, c, server, peerAddr, payload)
			data, from := waitPayload(t, peer, 3*time.Second)
			if !bytes.Equal(data, payload) {
				errCh <- fmt.Errorf("client %d got %q", i, data)
				return
			}
			if from.Port != relay.Port {
				errCh <- fmt.Errorf("client %d relay mismatch", i)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
