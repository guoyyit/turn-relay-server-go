package turn

import (
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// handleBinding answers a STUN Binding request with XOR-MAPPED-ADDRESS.
func (s *Server) handleBinding(msg *stun.Message, src *net.UDPAddr) {
	enc, err := stun.EncodeXorAddress(src.IP, src.Port, msg.TransactionID)
	if err != nil {
		return
	}
	resp := &stun.Message{
		Method:        stun.MethodBinding,
		Class:         stun.ClassSuccessResp,
		TransactionID: msg.TransactionID,
		Attributes: []stun.Attribute{
			{Type: stun.AttrXorMappedAddress, Data: enc},
		},
	}
	s.sendResponse(src, resp, nil)
}

func (s *Server) handleAllocate(raw []byte, msg *stun.Message, src *net.UDPAddr) {
	key, challenge := s.checkAuth(raw, msg, src)
	if key == nil {
		if challenge != nil {
			s.sendChallenge(stun.MethodAllocate, src, msg.TransactionID, challenge)
		}
		return
	}

	rt, hasRT := attrValue(msg, stun.AttrRequestedTransport)
	if !hasRT || len(rt) < 1 || rt[0] != 17 {
		s.sendMethodError(stun.MethodAllocate, src, msg.TransactionID, key,
			CodeUnsupportedTransport, "Unsupported Transport Protocol")
		return
	}

	s.mu.Lock()
	if existing, ok := s.allocations[src.String()]; ok && existing.active(time.Now()) {
		s.mu.Unlock()
		s.sendMethodError(stun.MethodAllocate, src, msg.TransactionID, key,
			CodeAllocMismatch, "Allocation Already Exists")
		return
	}
	s.mu.Unlock()

	alloc, err := s.createAllocation(src, attrUsername(msg))
	if err != nil {
		code := CodeInsufficientCapacity
		reason := "Insufficient Capacity"
		if te, ok := err.(*turnError); ok {
			code, reason = te.code, te.reason
		}
		s.sendMethodError(stun.MethodAllocate, src, msg.TransactionID, key, code, reason)
		return
	}

	s.mu.Lock()
	if other, ok := s.allocations[src.String()]; ok && other != alloc {
		s.mu.Unlock()
		alloc.close()
		s.sendMethodError(stun.MethodAllocate, src, msg.TransactionID, key,
			CodeAllocMismatch, "Allocation Already Exists")
		return
	}
	s.allocations[src.String()] = alloc
	s.mu.Unlock()

	lifetime := s.requestedLifetime(msg)
	alloc.setExpiry(time.Now().Add(lifetime))

	relayEnc, _ := stun.EncodeXorAddress(alloc.relayAddr.IP, alloc.relayAddr.Port, msg.TransactionID)
	mappedEnc, _ := stun.EncodeXorAddress(src.IP, src.Port, msg.TransactionID)
	resp := &stun.Message{
		Method:        stun.MethodAllocate,
		Class:         stun.ClassSuccessResp,
		TransactionID: msg.TransactionID,
		Attributes: []stun.Attribute{
			{Type: stun.AttrXorRelayedAddress, Data: relayEnc},
			{Type: stun.AttrXorMappedAddress, Data: mappedEnc},
			{Type: stun.AttrLifetime, Data: lifetimeSeconds(lifetime)},
		},
	}
	s.sendResponse(src, resp, key)
}

func (s *Server) handleRefresh(raw []byte, msg *stun.Message, alloc *Allocation, src *net.UDPAddr) {
	key, challenge := s.checkAuth(raw, msg, src)
	if key == nil {
		if challenge != nil {
			s.sendChallenge(stun.MethodRefresh, src, msg.TransactionID, challenge)
		}
		return
	}

	lifetime := s.requestedLifetime(msg)
	resp := &stun.Message{
		Method:        stun.MethodRefresh,
		Class:         stun.ClassSuccessResp,
		TransactionID: msg.TransactionID,
		Attributes: []stun.Attribute{
			{Type: stun.AttrLifetime, Data: lifetimeSeconds(lifetime)},
		},
	}
	if lifetime == 0 {
		s.removeAllocation(src.String())
	} else {
		alloc.setExpiry(time.Now().Add(lifetime))
	}
	s.sendResponse(src, resp, key)
}

func (s *Server) handleCreatePermission(raw []byte, msg *stun.Message, alloc *Allocation, src *net.UDPAddr) {
	key, challenge := s.checkAuth(raw, msg, src)
	if key == nil {
		if challenge != nil {
			s.sendChallenge(stun.MethodCreatePerm, src, msg.TransactionID, challenge)
		}
		return
	}

	peers, bad := requestedPeers(msg)
	if bad {
		s.sendMethodError(stun.MethodCreatePerm, src, msg.TransactionID, key,
			CodeBadRequest, "Bad Request")
		return
	}
	now := time.Now()
	for _, peer := range peers {
		alloc.refreshPermission(peer, now, s.config.PermissionLifetime)
	}
	resp := &stun.Message{
		Method:        stun.MethodCreatePerm,
		Class:         stun.ClassSuccessResp,
		TransactionID: msg.TransactionID,
	}
	s.sendResponse(src, resp, key)
}

func (s *Server) handleChannelBind(raw []byte, msg *stun.Message, alloc *Allocation, src *net.UDPAddr) {
	key, challenge := s.checkAuth(raw, msg, src)
	if key == nil {
		if challenge != nil {
			s.sendChallenge(stun.MethodChannelBind, src, msg.TransactionID, challenge)
		}
		return
	}

	numVal, hasNum := attrValue(msg, stun.AttrChannelNumber)
	peerVal, hasPeer := attrValue(msg, stun.AttrXorPeerAddress)
	if !hasNum || !hasPeer {
		s.sendMethodError(stun.MethodChannelBind, src, msg.TransactionID, key,
			CodeBadRequest, "Missing required attributes")
		return
	}
	number, ok := stun.DecodeChannelNumber(numVal)
	if !ok || number < stun.MinChannelNumber || number > stun.MaxChannelNumber {
		s.sendMethodError(stun.MethodChannelBind, src, msg.TransactionID, key,
			CodeBadRequest, "Channel Number out of range")
		return
	}
	ip, port, err := stun.DecodeXorAddress(peerVal, msg.TransactionID)
	if err != nil {
		s.sendMethodError(stun.MethodChannelBind, src, msg.TransactionID, key,
			CodeBadRequest, "Bad Peer Address")
		return
	}
	if err := alloc.bindChannel(number, ip, port, time.Now(), s.config.PermissionLifetime); err != nil {
		code, reason := CodeBadRequest, "Bad Request"
		if te, ok := err.(*turnError); ok {
			code, reason = te.code, te.reason
		}
		s.sendMethodError(stun.MethodChannelBind, src, msg.TransactionID, key, code, reason)
		return
	}
	resp := &stun.Message{
		Method:        stun.MethodChannelBind,
		Class:         stun.ClassSuccessResp,
		TransactionID: msg.TransactionID,
	}
	s.sendResponse(src, resp, key)
}

func (s *Server) handleSendIndication(msg *stun.Message, alloc *Allocation, src *net.UDPAddr) {
	peerVal, hasPeer := attrValue(msg, stun.AttrXorPeerAddress)
	dataVal, hasData := attrValue(msg, stun.AttrData)
	if !hasPeer || !hasData {
		return
	}
	ip, port, err := stun.DecodeXorAddress(peerVal, msg.TransactionID)
	if err != nil {
		return
	}
	if !alloc.hasPermission(ip, time.Now()) {
		return
	}
	payload := make([]byte, len(dataVal))
	copy(payload, dataVal)
	go sendToPeer(alloc, &net.UDPAddr{IP: ip, Port: port}, payload)
}

// ----- response helpers -----

func (s *Server) sendResponse(dst *net.UDPAddr, msg *stun.Message, key []byte) {
	var raw []byte
	var err error
	if key != nil {
		raw, err = msg.MarshalWithIntegrity(key)
	} else {
		raw, err = msg.Marshal()
	}
	if err != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(raw, dst)
}

func (s *Server) sendMethodError(method uint16, dst *net.UDPAddr, txID [12]byte, key []byte, code int, reason string) {
	resp := &stun.Message{
		Method:        method,
		Class:         stun.ClassErrorResp,
		TransactionID: txID,
		Attributes: []stun.Attribute{
			{Type: stun.AttrErrorCode, Data: stun.EncodeErrorCode(code, reason)},
		},
	}
	s.sendResponse(dst, resp, key)
}

// authChallenge describes a pending 401/438 challenge.
type authChallenge struct {
	code  int
	nonce string
}

func (s *Server) sendChallenge(method uint16, dst *net.UDPAddr, txID [12]byte, ch *authChallenge) {
	reason := "Unauthorized"
	code := CodeUnauthorized
	if ch.code == CodeStaleNonce {
		code, reason = CodeStaleNonce, "Stale Nonce"
	}
	resp := &stun.Message{
		Method:        method,
		Class:         stun.ClassErrorResp,
		TransactionID: txID,
		Attributes: []stun.Attribute{
			{Type: stun.AttrErrorCode, Data: stun.EncodeErrorCode(code, reason)},
			{Type: stun.AttrRealm, Data: []byte(s.auth.realm())},
			{Type: stun.AttrNonce, Data: []byte(ch.nonce)},
		},
	}
	raw, err := resp.Marshal()
	if err != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(raw, dst)
}

func attrValue(msg *stun.Message, t uint16) ([]byte, bool) {
	a, ok := msg.Attr(t)
	if !ok {
		return nil, false
	}
	return a.Data, true
}
