// Package stun implements encoding and decoding of STUN messages as defined
// in RFC 5389, together with the attribute types used by TURN (RFC 5766).
package stun

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"hash/crc32"
	"net"
	"time"
)

// MagicCookie is the fixed STUN magic cookie (RFC 5389 section 6).
const MagicCookie uint32 = 0x2112A442

// HeaderLen is the size in bytes of a STUN message header.
const HeaderLen = 20

// STUN methods.
const (
	MethodBinding          uint16 = 0x001
	MethodAllocate         uint16 = 0x003
	MethodRefresh          uint16 = 0x004
	MethodCreatePermission uint16 = 0x008
	MethodChannelBind      uint16 = 0x009
)

// STUN message classes.
const (
	ClassRequest    uint16 = 0x00
	ClassIndication uint16 = 0x01
	ClassSuccess    uint16 = 0x02
	ClassError      uint16 = 0x03
)

// Attribute types (RFC 5389 / RFC 5766).
const (
	AttrMappedAddress      uint16 = 0x0001
	AttrUsername           uint16 = 0x0006
	AttrMessageIntegrity   uint16 = 0x0008
	AttrErrorCode          uint16 = 0x0009
	AttrChannelNumber      uint16 = 0x000C
	AttrLifetime           uint16 = 0x000D
	AttrXorPeerAddress     uint16 = 0x0012
	AttrData               uint16 = 0x0013
	AttrRealm              uint16 = 0x0014
	AttrNonce              uint16 = 0x0015
	AttrXorRelayedAddress  uint16 = 0x0016
	AttrRequestedTransport uint16 = 0x0019
	AttrXorMappedAddress   uint16 = 0x0020
	AttrSoftware           uint16 = 0x8022
	AttrFingerprint        uint16 = 0x8028
)

// STUN/TURN error codes (RFC 5389 15.6, RFC 5766 6.4).
const (
	StatusBadRequest           = 400
	StatusUnauthenticated      = 401
	StatusUnknownAttribute     = 420
	StatusAllocMismatch        = 437
	StatusStaleNonce           = 438
	StatusWrongCredentials     = 441
	StatusUnsupportedTransport = 442
	StatusAllocQuotaExceeded   = 443
	StatusInsufficientCapacity = 508
)

// ErrMalformed is returned when a datagram is not a valid STUN message.
var ErrMalformed = errors.New("stun: malformed message")

// Attribute is a single type-length-value STUN attribute.
type Attribute struct {
	Type  uint16
	Value []byte
}

// Message represents a decoded STUN message.
type Message struct {
	method uint16
	class  uint16
	txID   [12]byte
	attrs  []Attribute

	raw     []byte // original datagram, retained for integrity verification
	miStart int    // offset of MESSAGE-INTEGRITY header in raw (-1 if absent)
	fpStart int    // offset of FINGERPRINT header in raw (-1 if absent)
}

// New returns a message with the given method, class and transaction id.
func New(method, class uint16, txID []byte) *Message {
	m := &Message{method: method, class: class, miStart: -1, fpStart: -1}
	copy(m.txID[:], txID)
	return m
}

// Parse decodes a STUN datagram.
func Parse(b []byte) (*Message, error) {
	if len(b) < HeaderLen || b[0]&0xC0 != 0 {
		return nil, ErrMalformed
	}
	msgType := uint16(b[0])<<8 | uint16(b[1])
	payloadLen := int(uint16(b[2])<<8 | uint16(b[3]))
	if payloadLen+HeaderLen != len(b) {
		return nil, ErrMalformed
	}
	cookie := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	if cookie != MagicCookie {
		return nil, ErrMalformed
	}

	m := &Message{raw: b, miStart: -1, fpStart: -1}
	m.method, m.class = SplitType(msgType)
	copy(m.txID[:], b[8:20])

	off := HeaderLen
	end := HeaderLen + payloadLen
	for off < end {
		if end-off < 4 {
			return nil, ErrMalformed
		}
		at := uint16(b[off])<<8 | uint16(b[off+1])
		al := int(uint16(b[off+2])<<8 | uint16(b[off+3]))
		vStart := off + 4
		if al > end-vStart {
			return nil, ErrMalformed
		}
		value := make([]byte, al)
		copy(value, b[vStart:vStart+al])
		switch at {
		case AttrMessageIntegrity:
			if al != sha1.Size {
				return nil, ErrMalformed
			}
			m.miStart = off
		case AttrFingerprint:
			if al != 4 {
				return nil, ErrMalformed
			}
			m.fpStart = off
		}
		m.attrs = append(m.attrs, Attribute{Type: at, Value: value})
		off = vStart + (al+3)&^3
	}
	return m, nil
}

// JoinType encodes a method and class into a STUN message type field.
func JoinType(method, class uint16) uint16 {
	return (method&0x0F80)<<2 | (method&0x0070)<<1 | (method & 0x000F) |
		(class&0x2)<<7 | (class&1)<<4
}

// SplitType extracts the method and class from a message type field.
func SplitType(t uint16) (method, class uint16) {
	method = (t&0x3E00)>>2 | (t&0x00E0)>>1 | (t & 0x000F)
	class = (t&0x0100)>>7 | (t&0x0010)>>4
	return
}

// Method returns the STUN method.
func (m *Message) Method() uint16 { return m.method }

// Class returns the STUN message class.
func (m *Message) Class() uint16 { return m.class }

// TxID returns the 12-byte transaction id.
func (m *Message) TxID() [12]byte { return m.txID }

// TxIDBytes returns a copy of the transaction id as a slice.
func (m *Message) TxIDBytes() []byte {
	return m.txID[:]
}

// Add appends a raw attribute.
func (m *Message) Add(t uint16, value []byte) {
	m.attrs = append(m.attrs, Attribute{Type: t, Value: value})
}

// AddString appends a UTF-8 string attribute.
func (m *Message) AddString(t uint16, value string) {
	m.Add(t, []byte(value))
}

// String reads a UTF-8 string attribute.
func (m *Message) String(t uint16) (string, bool) {
	if a, ok := m.find(t); ok {
		return string(a.Value), true
	}
	return "", false
}

// AddUint32 appends a four-byte unsigned integer attribute.
func (m *Message) AddUint32(t uint16, value uint32) {
	m.Add(t, []byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// Uint32 reads a four-byte unsigned integer attribute.
func (m *Message) Uint32(t uint16) (uint32, bool) {
	a, ok := m.find(t)
	if !ok || len(a.Value) != 4 {
		return 0, false
	}
	return uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 |
		uint32(a.Value[2])<<8 | uint32(a.Value[3]), true
}

// AddLifetime encodes a duration as whole seconds (rounded up).
func (m *Message) AddLifetime(t uint16, d time.Duration) {
	secs := uint32((d + time.Second - 1) / time.Second)
	m.AddUint32(t, secs)
}

// Lifetime reads a duration attribute expressed in seconds.
func (m *Message) Lifetime(t uint16) (time.Duration, bool) {
	v, ok := m.Uint32(t)
	if !ok {
		return 0, false
	}
	return time.Duration(v) * time.Second, true
}

// find returns the first attribute of the given type.
func (m *Message) find(t uint16) (*Attribute, bool) {
	for i := range m.attrs {
		if m.attrs[i].Type == t {
			return &m.attrs[i], true
		}
	}
	return nil, false
}

// All returns all attributes of the given type.
func (m *Message) All(t uint16) []Attribute {
	var out []Attribute
	for i := range m.attrs {
		if m.attrs[i].Type == t {
			out = append(out, m.attrs[i])
		}
	}
	return out
}

func putBE16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putBE32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func hmacSHA1(key, b []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(b)
	return mac.Sum(nil)
}

// addressMask returns the 16-byte XOR mask (cookie || transaction id).
func (m *Message) addressMask() []byte {
	return addressMask(&m.txID)
}

func addressMask(txID *[12]byte) []byte {
	mask := make([]byte, 16)
	putBE32(mask, MagicCookie)
	copy(mask[4:], txID[:])
	return mask
}

// AddXorAddress appends an XOR-encoded IPv4/IPv6 socket address attribute.
func (m *Message) AddXorAddress(t uint16, addr *net.UDPAddr) {
	if ip4 := addr.IP.To4(); ip4 != nil {
		v := make([]byte, 0, 8)
		v = append(v, 0, 0x01)
		xport := uint16(addr.Port) ^ uint16(MagicCookie>>16)
		v = append(v, byte(xport>>8), byte(xport))
		for i := 0; i < 4; i++ {
			v = append(v, ip4[i]^byte(MagicCookie>>(24-8*i)))
		}
		m.Add(t, v)
		return
	}
	ip6 := addr.IP.To16()
	v := make([]byte, 0, 20)
	v = append(v, 0, 0x02)
	xport := uint16(addr.Port) ^ uint16(MagicCookie>>16)
	v = append(v, byte(xport>>8), byte(xport))
	mask := m.addressMask()
	for i := 0; i < 16; i++ {
		v = append(v, ip6[i]^mask[i])
	}
	m.Add(t, v)
}

// XorAddress decodes an XOR-encoded socket address attribute.
func (m *Message) XorAddress(t uint16) (*net.UDPAddr, error) {
	a, ok := m.find(t)
	if !ok || len(a.Value) < 4 {
		return nil, ErrMalformed
	}
	return decodeXorAddress(a.Value, &m.txID)
}

// decodeXorAddress decodes one XOR-*ADDRESS attribute value.
func decodeXorAddress(v []byte, txID *[12]byte) (*net.UDPAddr, error) {
	if len(v) < 4 {
		return nil, ErrMalformed
	}
	xport := uint16(v[2])<<8 | uint16(v[3])
	port := xport ^ uint16(MagicCookie>>16)
	var ip net.IP
	switch v[1] {
	case 0x01:
		if len(v) != 8 {
			return nil, ErrMalformed
		}
		ip = make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = v[4+i] ^ byte(MagicCookie>>(24-8*i))
		}
	case 0x02:
		if len(v) != 20 {
			return nil, ErrMalformed
		}
		mask := addressMask(txID)
		ip = make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = v[4+i] ^ mask[i]
		}
	default:
		return nil, ErrMalformed
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// Peers decodes every XOR-PEER-ADDRESS attribute (RFC 5766 CreatePermission).
func (m *Message) Peers() []*net.UDPAddr {
	var peers []*net.UDPAddr
	for i := range m.attrs {
		if m.attrs[i].Type != AttrXorPeerAddress {
			continue
		}
		if addr, err := decodeXorAddress(m.attrs[i].Value, &m.txID); err == nil {
			peers = append(peers, addr)
		}
	}
	return peers
}

// AddErrorCode appends an ERROR-CODE attribute.
func (m *Message) AddErrorCode(code int, reason string) {
	v := []byte{0, 0, byte(code / 100), byte(code % 100)}
	v = append(v, []byte(reason)...)
	m.Add(AttrErrorCode, v)
}

// Data returns the bytes of the DATA attribute, when present.
func (m *Message) Data() ([]byte, bool) {
	if a, ok := m.find(AttrData); ok {
		return a.Value, true
	}
	return nil, false
}

// ErrorCode reads the ERROR-CODE attribute.
func (m *Message) ErrorCode() (code int, reason string, err error) {
	a, ok := m.find(AttrErrorCode)
	if !ok || len(a.Value) < 4 {
		return 0, "", ErrMalformed
	}
	code = int(a.Value[2]&0x07)*100 + int(a.Value[3])
	reason = string(a.Value[4:])
	return code, reason, nil
}

// AddChannelNumber appends a CHANNEL-NUMBER attribute.
func (m *Message) AddChannelNumber(number uint16) {
	m.AddUint32(AttrChannelNumber, uint32(number)<<16)
}

// ChannelNumber reads the CHANNEL-NUMBER attribute.
func (m *Message) ChannelNumber() (uint16, error) {
	v, ok := m.Uint32(AttrChannelNumber)
	if !ok {
		return 0, ErrMalformed
	}
	if v&0x0000FFFF != 0 {
		return 0, ErrMalformed
	}
	return uint16(v >> 16), nil
}

// AddIntegrity appends MESSAGE-INTEGRITY computed with the long-term key.
func (m *Message) AddIntegrity(key []byte) {
	b := m.serializeHeaderAttrs(4 + sha1.Size)
	mac := hmacSHA1(key, b)
	m.Add(AttrMessageIntegrity, mac)
}

// CheckIntegrity validates MESSAGE-INTEGRITY against key.
func (m *Message) CheckIntegrity(key []byte) bool {
	if m.miStart < 0 || len(m.raw) < m.miStart+4+sha1.Size {
		return false
	}
	prefix := make([]byte, m.miStart)
	copy(prefix, m.raw[:m.miStart])
	putBE16(prefix[2:], uint16(m.miStart-HeaderLen+4+sha1.Size))
	want := m.raw[m.miStart+4 : m.miStart+4+sha1.Size]
	return hmac.Equal(hmacSHA1(key, prefix), want)
}

// AddFingerprint appends a FINGERPRINT attribute; add it after integrity.
func (m *Message) AddFingerprint() {
	b := m.serializeHeaderAttrs(4 + 4)
	crc := crc32.ChecksumIEEE(b) ^ 0x5354554E
	m.AddUint32(AttrFingerprint, crc)
}

// FingerprintOK validates FINGERPRINT when the message contains one.
func (m *Message) FingerprintOK() bool {
	if m.fpStart < 0 || len(m.raw) < m.fpStart+8 {
		return false
	}
	prefix := make([]byte, m.fpStart)
	copy(prefix, m.raw[:m.fpStart])
	putBE16(prefix[2:], uint16(m.fpStart-HeaderLen+8))
	want := uint32(m.raw[m.fpStart+4])<<24 |
		uint32(m.raw[m.fpStart+5])<<16 |
		uint32(m.raw[m.fpStart+6])<<8 |
		uint32(m.raw[m.fpStart+7])
	return crc32.ChecksumIEEE(prefix)^0x5354554E == want
}

// Marshal serialises the message into a datagram.
func (m *Message) Marshal() ([]byte, error) {
	return m.serializeHeaderAttrs(0), nil
}

// serializeHeaderAttrs writes header and all attributes. When extraLen is
// non-zero the header length pretends a final attribute of that size exists;
// MESSAGE-INTEGRITY and FINGERPRINT need that view of the message.
func (m *Message) serializeHeaderAttrs(extraLen int) []byte {
	var body []byte
	for _, a := range m.attrs {
		body = append(body, byte(a.Type>>8), byte(a.Type),
			byte(len(a.Value)>>8), byte(len(a.Value)))
		body = append(body, a.Value...)
		if pad := (4 - len(a.Value)%4) % 4; pad > 0 {
			body = append(body, make([]byte, pad)...)
		}
	}
	totalLen := len(body) + extraLen
	out := make([]byte, 0, HeaderLen+totalLen)
	t := JoinType(m.method, m.class)
	out = append(out, byte(t>>8), byte(t),
		byte(totalLen>>8), byte(totalLen))
	cookie := MagicCookie
	out = append(out, byte(cookie>>24), byte(cookie>>16),
		byte(cookie>>8), byte(cookie))
	out = append(out, m.txID[:]...)
	out = append(out, body...)
	return out
}
