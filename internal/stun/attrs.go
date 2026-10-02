package stun

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
)

const fingerprintXOR = uint32(0x5354554E)

// Channel number range (RFC 5766 11).
const (
	MinChannelNumber = 0x4000
	MaxChannelNumber = 0x7FFF
)

func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func Uint32Attr(v []byte) (uint32, bool) {
	if len(v) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

func crc32IEEE(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}

// EncodeXorAddress encodes an IPv4 XOR-* attribute value.
func EncodeXorAddress(ip net.IP, port int, txID [12]byte) ([]byte, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("stun: only IPv4 supported")
	}
	out := make([]byte, 8)
	out[1] = 0x01 // IPv4
	xport := uint16(port) ^ uint16(MagicCookie>>16)
	binary.BigEndian.PutUint16(out[2:4], xport)
	for i := 0; i < 4; i++ {
		out[4+i] = ip4[i] ^ byte(MagicCookie>>(24-8*i))
	}
	return out, nil
}

// DecodeXorAddress decodes an XOR-* attribute value (IPv4 only).
func DecodeXorAddress(v []byte, txID [12]byte) (net.IP, int, error) {
	if len(v) < 8 || v[1] != 0x01 {
		return nil, 0, errors.New("stun: unsupported address family")
	}
	xport := binary.BigEndian.Uint16(v[2:4])
	port := xport ^ uint16(MagicCookie>>16)
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = v[4+i] ^ byte(MagicCookie>>(24-8*i))
	}
	return ip, int(port), nil
}

// EncodeErrorCode encodes an ERROR-CODE attribute value.
func EncodeErrorCode(code int, reason string) []byte {
	out := make([]byte, 0, 4+len(reason))
	out = append(out, 0, 0, byte((code/100)&0x7), byte(code%100))
	out = append(out, []byte(reason)...)
	return out
}

// DecodeErrorCode decodes an ERROR-CODE attribute value.
func DecodeErrorCode(v []byte) (int, string) {
	if len(v) < 4 {
		return 0, ""
	}
	cls := int(v[2] & 0x7)
	num := int(v[3])
	return cls*100 + num, string(v[4:])
}

// EncodeChannelNumber encodes a CHANNEL-NUMBER attribute value.
func EncodeChannelNumber(n uint16) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint16(out[0:2], n)
	return out
}

// DecodeChannelNumber decodes a CHANNEL-NUMBER attribute value.
func DecodeChannelNumber(v []byte) (uint16, bool) {
	if len(v) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(v[0:2]), true
}
