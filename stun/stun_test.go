package stun

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestRoundTripBasic(t *testing.T) {
	txID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	m := New(MethodBinding, ClassRequest, txID)
	m.AddString(AttrUsername, "alice")
	m.AddUint32(AttrLifetime, 600)
	m.AddLifetime(AttrLifetime, 600*time.Second)

	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Method() != MethodBinding || got.Class() != ClassRequest {
		t.Fatalf("type = %x/%x", got.Method(), got.Class())
	}
	if got.TxID() != m.TxID() {
		t.Fatal("transaction id mismatch")
	}
	if u, ok := got.String(AttrUsername); !ok || u != "alice" {
		t.Fatalf("username = %q ok=%v", u, ok)
	}
	if v, ok := got.Uint32(AttrLifetime); !ok || v != 600 {
		t.Fatalf("uint32 lifetime = %d ok=%v", v, ok)
	}
	if d, ok := got.Lifetime(AttrLifetime); !ok || d != 600*time.Second {
		t.Fatalf("lifetime = %v ok=%v", d, ok)
	}
}

func TestSplitJoinType(t *testing.T) {
	for _, mt := range []struct{ method, class uint16 }{
		{MethodBinding, ClassRequest},
		{MethodAllocate, ClassSuccess},
		{MethodChannelBind, ClassError},
		{MethodCreatePermission, ClassIndication},
	} {
		got := JoinType(mt.method, mt.class)
		m, c := SplitType(got)
		if m != mt.method || c != mt.class {
			t.Fatalf("round trip %x/%x -> %x/%x", mt.method, mt.class, m, c)
		}
	}
}

func TestXorAddressV4(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 42563}
	m := New(MethodBinding, ClassSuccess, bytes.Repeat([]byte{0xAB}, 12))
	m.AddXorAddress(AttrXorMappedAddress, addr)
	b, _ := m.Marshal()
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := got.XorAddress(AttrXorMappedAddress)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != addr.String() {
		t.Fatalf("addr = %s, want %s", out, addr)
	}
}

func TestErrorCode(t *testing.T) {
	m := New(MethodAllocate, ClassError, nil)
	m.AddErrorCode(437, "Allocation Mismatch")
	b, _ := m.Marshal()
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	code, reason, err := got.ErrorCode()
	if err != nil || code != 437 || reason != "Allocation Mismatch" {
		t.Fatalf("code=%d reason=%q err=%v", code, reason, err)
	}
}

func TestChannelNumber(t *testing.T) {
	m := New(MethodChannelBind, ClassRequest, nil)
	m.AddChannelNumber(0x4020)
	b, _ := m.Marshal()
	got, _ := Parse(b)
	n, err := got.ChannelNumber()
	if err != nil || n != 0x4020 {
		t.Fatalf("number=%x err=%v", n, err)
	}
}

func TestIntegrityAndFingerprint(t *testing.T) {
	key := []byte("long-term-key")
	m := New(MethodAllocate, ClassRequest, []byte("txid-txid-txid"))
	m.AddString(AttrUsername, "alice")
	m.AddString(AttrRealm, "turn.local")
	m.AddString(AttrNonce, "nonce")
	m.AddIntegrity(key)
	m.AddFingerprint()

	b, _ := m.Marshal()
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.FingerprintOK() {
		t.Fatal("fingerprint check failed")
	}
	if !got.CheckIntegrity(key) {
		t.Fatal("integrity check failed")
	}
	if got.CheckIntegrity([]byte("wrong-key")) {
		t.Fatal("integrity accepted wrong key")
	}
}

func TestParseMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 10),
		// leading bits set
		bytes.Repeat([]byte{0xFF}, 20),
		// wrong length
		append([]byte{0, 1, 0, 99, 0x21, 0x12, 0xA4, 0x42}, make([]byte, 12)...),
	}
	for i, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestPeers(t *testing.T) {
	m := New(MethodCreatePermission, ClassRequest, nil)
	p1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7000}
	p2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7001}
	m.AddXorAddress(AttrXorPeerAddress, p1)
	m.AddXorAddress(AttrXorPeerAddress, p2)
	peers := m.Peers()
	if len(peers) != 2 || peers[0].String() != p1.String() ||
		peers[1].String() != p2.String() {
		t.Fatalf("peers = %v", peers)
	}
}
