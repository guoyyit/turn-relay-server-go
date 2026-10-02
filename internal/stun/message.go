package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

// STUN magic cookie (RFC 5389).
const MagicCookie = uint32(0x2112A442)

// Header size in bytes.
const HeaderSize = 20

// Attribute type constants.
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
	AttrFingerprint        uint16 = 0x8028
)

// Method constants.
const (
	MethodBinding     uint16 = 0x001
	MethodAllocate    uint16 = 0x003
	MethodRefresh     uint16 = 0x004
	MethodSend        uint16 = 0x006
	MethodData        uint16 = 0x007
	MethodCreatePerm  uint16 = 0x008
	MethodChannelBind uint16 = 0x009
)

// Class constants.
const (
	ClassRequest     uint16 = 0b00
	ClassIndication  uint16 = 0b01
	ClassSuccessResp uint16 = 0b10
	ClassErrorResp   uint16 = 0b11
)

// Known protocol errors.
var (
	ErrShortMessage   = errors.New("stun: message too short")
	ErrBadMagicCookie = errors.New("stun: bad magic cookie")
	ErrBadFingerprint = errors.New("stun: fingerprint mismatch")
	ErrBadIntegrity   = errors.New("stun: message-integrity mismatch")
)

// Attribute represents a single STUN/TURN attribute.
type Attribute struct {
	Type uint16
	Data []byte
}

// Message represents a STUN/TURN message.
type Message struct {
	Method        uint16
	Class         uint16
	TransactionID [12]byte
	Attributes    []Attribute
}

// Parse decodes a STUN message from bytes.
func Parse(b []byte) (*Message, error) {
	if len(b) < HeaderSize {
		return nil, ErrShortMessage
	}
	msgType := binary.BigEndian.Uint16(b[0:2])
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if binary.BigEndian.Uint32(b[4:8]) != MagicCookie {
		return nil, ErrBadMagicCookie
	}
	if len(b) != HeaderSize+msgLen {
		return nil, errors.New("stun: message length mismatch")
	}

	m := &Message{
		Method: decodeMethod(msgType),
		Class:  decodeClass(msgType),
	}
	copy(m.TransactionID[:], b[8:20])

	p := HeaderSize
	for p < len(b) {
		if p+4 > len(b) {
			return nil, errors.New("stun: truncated attribute header")
		}
		at := binary.BigEndian.Uint16(b[p : p+2])
		al := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		start := p + 4
		end := start + al
		if end > len(b) {
			return nil, errors.New("stun: truncated attribute value")
		}
		val := make([]byte, al)
		copy(val, b[start:end])
		m.Attributes = append(m.Attributes, Attribute{Type: at, Data: val})
		p = end + padSize(al)
	}
	return m, nil
}

// Marshal encodes the message without integrity or fingerprint.
func (m *Message) Marshal() ([]byte, error) {
	return m.marshal(nil), nil
}

// MarshalWithIntegrity encodes the message with MESSAGE-INTEGRITY and FINGERPRINT.
func (m *Message) MarshalWithIntegrity(key []byte) ([]byte, error) {
	return m.marshal(key), nil
}

// AddFingerprint appends a FINGERPRINT attribute to a marshaled message.
func addFingerprint(b []byte) []byte {
	// CRC-32 covers the bytes up to (but excluding) FINGERPRINT, with the
	// message length field already reflecting the final size.
	out := make([]byte, 0, len(b)+8)
	out = append(out, b...)
	out = appendAttr(out, AttrFingerprint, make([]byte, 4))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-HeaderSize))
	crc := crc32IEEE(out[:len(out)-8]) ^ fingerprintXOR
	copy(out[len(out)-4:], uint32Bytes(crc))
	return out
}

// MarshalChannelData encodes a ChannelData message.
func MarshalChannelData(channel uint16, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 0xFFFF {
		return nil, errors.New("stun: channel data length out of range")
	}
	total := 4 + len(data)
	padded := 4 + len(data) + padSize(len(data))
	out := make([]byte, padded)
	binary.BigEndian.PutUint16(out[0:2], channel)
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:], data)
	return out, nil
}

// ParseChannelData decodes a ChannelData message.
func ParseChannelData(b []byte) (channel uint16, data []byte, err error) {
	if len(b) < 4 {
		return 0, nil, errors.New("stun: channeldata too short")
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < 4 || total > len(b) {
		return 0, nil, errors.New("stun: channeldata bad length")
	}
	if total+padSize(total) > len(b) {
		return 0, nil, errors.New("stun: channeldata truncated padding")
	}
	return binary.BigEndian.Uint16(b[0:2]), b[4:total], nil
}

// IsChannelData reports whether a datagram is a ChannelData message.
func IsChannelData(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	ch := binary.BigEndian.Uint16(b[0:2])
	total := int(binary.BigEndian.Uint16(b[2:4]))
	return ch >= MinChannelNumber && ch <= MaxChannelNumber &&
		total >= 4 && total+padSize(total) <= len(b)
}

// LongTermKey derives the long-term credential key (RFC 5389 15.4).
func LongTermKey(username, realm, password string) []byte {
	h := sha1.Sum([]byte(username + ":" + realm + ":" + password))
	return h[:]
}

func hmacSHA1(key, content []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(content)
	sum := mac.Sum(nil)
	out := make([]byte, len(sum))
	copy(out, sum)
	return out
}

// ----- internal encoding helpers -----

func (m *Message) marshal(key []byte) []byte {
	b := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(b[0:2], encodeType(m.Method, m.Class))
	binary.BigEndian.PutUint32(b[4:8], MagicCookie)
	copy(b[8:20], m.TransactionID[:])
	for _, a := range m.Attributes {
		b = appendAttr(b, a.Type, a.Data)
	}

	if key != nil {
		// MESSAGE-INTEGRITY is computed with the length field covering
		// everything up to and including the 24-byte MI attribute.
		lengthBefore := len(b) - HeaderSize
		b = appendAttr(b, AttrMessageIntegrity, make([]byte, 20))
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-HeaderSize))
		mac := hmacSHA1(key, b)
		copy(b[len(b)-20:], mac)

		b = addFingerprint(b)
		_ = lengthBefore
	} else {
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-HeaderSize))
	}
	return b
}

// FingerprintOK validates the FINGERPRINT attribute of a raw message.
func FingerprintOK(raw []byte) bool {
	off, ok := attrOffset(raw, AttrFingerprint)
	if !ok || off+8 != len(raw) {
		return false
	}
	want := binary.BigEndian.Uint32(raw[off+4 : off+8])
	prefix := make([]byte, off)
	copy(prefix, raw[:off])
	binary.BigEndian.PutUint16(prefix[2:4], uint16(len(raw)-HeaderSize))
	return crc32IEEE(prefix)^fingerprintXOR == want
}

// MessageIntegrityOK validates MESSAGE-INTEGRITY against the given key.
func MessageIntegrityOK(raw []byte, key []byte) bool {
	off, ok := attrOffset(raw, AttrMessageIntegrity)
	if !ok || off+24 > len(raw) {
		return false
	}
	want := raw[off+4 : off+24]
	prefix := make([]byte, off+24)
	copy(prefix, raw[:off+24])
	binary.BigEndian.PutUint16(prefix[2:4], uint16(off+24-HeaderSize))
	// The HMAC was computed with the MI value as a 20-byte placeholder.
	for i := off + 4; i < off+24; i++ {
		prefix[i] = 0
	}
	return bytes.Equal(hmacSHA1(key, prefix), want)
}

// Attr returns the first attribute of the given type and whether it exists.
func (m *Message) Attr(t uint16) (Attribute, bool) {
	for _, a := range m.Attributes {
		if a.Type == t {
			return a, true
		}
	}
	return Attribute{}, false
}

func attrOffset(raw []byte, t uint16) (int, bool) {
	msgLen := int(binary.BigEndian.Uint16(raw[2:4]))
	end := HeaderSize + msgLen
	p := HeaderSize
	for p+4 <= end {
		at := binary.BigEndian.Uint16(raw[p : p+2])
		al := int(binary.BigEndian.Uint16(raw[p+2 : p+4]))
		if at == t {
			return p, true
		}
		p += 4 + al + padSize(al)
	}
	return 0, false
}

func appendAttr(b []byte, t uint16, v []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], t)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(v)))
	b = append(b, hdr[0], hdr[1], hdr[2], hdr[3])
	b = append(b, v...)
	if pad := padSize(len(v)); pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

func padSize(n int) int { return (4 - n%4) % 4 }

func encodeType(method, class uint16) uint16 {
	// RFC 5389: M0..M3 at 0..3, C0 at 4, M4..M6 at 5..7,
	// C1 at 8, M7..M11 at 9..13.
	return (method & 0x000F) |
		((class & 0x1) << 4) |
		((method & 0x0070) << 1) |
		((class & 0x2) << 7) |
		((method & 0x0F80) << 2)
}

func decodeMethod(t uint16) uint16 {
	return (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x3E00)
}

func decodeClass(t uint16) uint16 {
	return ((t >> 4) & 0x1) | (((t >> 8) & 0x1) << 1)
}
