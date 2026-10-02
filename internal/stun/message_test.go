package stun

import (
	"net"
	"testing"
)

func TestParseMarshalBinding(t *testing.T) {
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	m := &Message{
		Method:        MethodBinding,
		Class:         ClassRequest,
		TransactionID: tx,
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != HeaderSize {
		t.Fatalf("unexpected length %d", len(raw))
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Method != MethodBinding || parsed.Class != ClassRequest {
		t.Fatalf("bad type: method=%x class=%x", parsed.Method, parsed.Class)
	}
	if parsed.TransactionID != tx {
		t.Fatal("transaction id mismatch")
	}
}

func TestXorAddressRoundTrip(t *testing.T) {
	tx := [12]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1}
	ip := net.IPv4(127, 0, 0, 1)
	enc, err := EncodeXorAddress(ip, 54321, tx)
	if err != nil {
		t.Fatal(err)
	}
	gotIP, gotPort, err := DecodeXorAddress(enc, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !gotIP.Equal(ip) || gotPort != 54321 {
		t.Fatalf("round trip mismatch: %v:%d", gotIP, gotPort)
	}
}

func TestFingerprintAndIntegrity(t *testing.T) {
	tx := [12]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3}
	key := LongTermKey("user", "realm", "pass")
	m := &Message{
		Method:        MethodAllocate,
		Class:         ClassRequest,
		TransactionID: tx,
		Attributes: []Attribute{
			{Type: AttrUsername, Data: []byte("user")},
		},
	}
	raw, err := m.MarshalWithIntegrity(key)
	if err != nil {
		t.Fatal(err)
	}
	if !FingerprintOK(raw) {
		t.Fatal("fingerprint check failed")
	}
	if !MessageIntegrityOK(raw, key) {
		t.Fatal("integrity check failed")
	}
	if MessageIntegrityOK(raw, []byte("wrong")) {
		t.Fatal("integrity unexpectedly accepted wrong key")
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Method != MethodAllocate {
		t.Fatal("method mismatch")
	}
}

func TestErrorCodeRoundTrip(t *testing.T) {
	enc := EncodeErrorCode(437, "Allocation Mismatch")
	code, reason := DecodeErrorCode(enc)
	if code != 437 || reason != "Allocation Mismatch" {
		t.Fatalf("got %d %q", code, reason)
	}
}

func TestChannelDataRoundTrip(t *testing.T) {
	payload := []byte("hello channel")
	raw, err := MarshalChannelData(0x4000, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !IsChannelData(raw) {
		t.Fatal("IsChannelData rejected valid frame")
	}
	ch, data, err := ParseChannelData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch != 0x4000 || string(data) != string(payload) {
		t.Fatalf("channel data mismatch: %d %q", ch, data)
	}
	if IsChannelData([]byte{0x12, 0x34, 4, 0, 0, 0, 0, 0}) {
		t.Fatal("IsChannelData accepted out-of-range channel")
	}
}
