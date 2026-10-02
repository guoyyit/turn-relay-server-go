package turn

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// checkAuth validates the long-term credentials of an authenticated request.
// It returns the HMAC key on success, or an authChallenge describing the
// 401/438 response that must be sent.
func (s *Server) checkAuth(raw []byte, msg *stun.Message, src *net.UDPAddr) ([]byte, *authChallenge) {
	nonceVal, hasNonce := attrValue(msg, stun.AttrNonce)
	userVal, hasUser := attrValue(msg, stun.AttrUsername)
	if !hasNonce || !hasUser || len(nonceVal) == 0 || len(userVal) == 0 {
		return nil, &authChallenge{code: CodeUnauthorized, nonce: s.auth.issueNonce()}
	}
	key, stale, ok := s.auth.validate(string(nonceVal), string(userVal))
	if stale {
		return nil, &authChallenge{code: CodeStaleNonce, nonce: s.auth.issueNonce()}
	}
	if !ok {
		return nil, &authChallenge{code: CodeUnauthorized, nonce: s.auth.issueNonce()}
	}
	if _, hasMI := attrValue(msg, stun.AttrMessageIntegrity); !hasMI ||
		!stun.MessageIntegrityOK(raw, key) {
		return nil, &authChallenge{code: CodeUnauthorized, nonce: s.auth.issueNonce()}
	}
	return key, nil
}

func attrUsername(msg *stun.Message) string {
	if v, ok := attrValue(msg, stun.AttrUsername); ok {
		return string(v)
	}
	return ""
}

// requestedLifetime parses and clamps the LIFETIME attribute.
func (s *Server) requestedLifetime(msg *stun.Message) time.Duration {
	if v, ok := attrValue(msg, stun.AttrLifetime); ok {
		if secs, valid := stun.Uint32Attr(v); valid {
			d := time.Duration(secs) * time.Second
			if d > s.config.MaxLifetime {
				return s.config.MaxLifetime
			}
			return d
		}
	}
	return s.config.DefaultLifetime
}

// requestedPeers extracts all XOR-PEER-ADDRESS attributes (IPv4 only).
func requestedPeers(msg *stun.Message) ([]net.IP, bool) {
	var peers []net.IP
	found := false
	for _, a := range msg.Attributes {
		if a.Type != stun.AttrXorPeerAddress {
			continue
		}
		found = true
		ip, _, err := stun.DecodeXorAddress(a.Data, msg.TransactionID)
		if err != nil || ip.To4() == nil {
			return nil, true
		}
		peers = append(peers, ip)
	}
	if !found {
		return nil, true
	}
	return peers, false
}

func lifetimeSeconds(d time.Duration) []byte {
	secs := uint32(d / time.Second)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, secs)
	return out
}
