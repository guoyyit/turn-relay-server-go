package turn

import "errors"

// ChannelDataHeaderLen is the fixed 4-byte ChannelData header length.
const ChannelDataHeaderLen = 4

// IsChannelData reports whether a datagram begins with a ChannelData frame
// rather than a STUN message: STUN message types start with a zero top bit,
// whereas valid channel numbers (0x4000-0x4FFF) have top bits 01.
func IsChannelData(b []byte) bool {
	return len(b) >= ChannelDataHeaderLen && b[0]&0xC0 == 0x40
}

// ErrChannelData indicates a malformed ChannelData frame.
var ErrChannelData = errors.New("turn: malformed channel data")

// ParseChannelData decodes one ChannelData frame.
func ParseChannelData(b []byte) (number uint16, data []byte, err error) {
	if !IsChannelData(b) {
		return 0, nil, ErrChannelData
	}
	number = uint16(b[0])<<8 | uint16(b[1])
	length := int(uint16(b[2])<<8 | uint16(b[3]))
	if length < 4 || ChannelDataHeaderLen+length > len(b) {
		return 0, nil, ErrChannelData
	}
	return number, append([]byte(nil), b[4:4+length]...), nil
}

// MarshalChannelData frames data for the given channel number.
func MarshalChannelData(number uint16, data []byte) []byte {
	padded := (len(data) + 3) &^ 3
	out := make([]byte, ChannelDataHeaderLen+padded)
	out[0] = byte(number >> 8)
	out[1] = byte(number)
	out[2] = byte(len(data) >> 8)
	out[3] = byte(len(data))
	copy(out[4:], data)
	return out
}
