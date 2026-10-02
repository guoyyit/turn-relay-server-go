package turn

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

// STUN methods for TURN indications (RFC 5766 section 2.2).
const (
	methodSend = 0x006
	methodData = 0x007
)

func newTxID() []byte {
	txID := make([]byte, 12)
	_, _ = rand.Read(txID)
	return txID
}

func (s *Server) handleRequest(msg *stun.Message, src *net.UDPAddr) *stun.Message {
	switch msg.Method() {
	case stun.MethodBinding:
		return s.handleBinding(msg, src)
	case stun.MethodAllocate:
		return s.handleAllocate(msg, src)
	case stun.MethodRefresh:
		return s.handleRefresh(msg, src)
	case stun.MethodCreatePermission:
		return s.handleCreatePermission(msg, src)
	case stun.MethodChannelBind:
		return s.handleChannelBind(msg, src)
	default:
		return s.errorResponse(msg, stun.StatusBadRequest, "Unsupported STUN method", false, nil)
	}
}

func (s *Server) handleBinding(req *stun.Message, src *net.UDPAddr) *stun.Message {
	resp := stun.New(stun.MethodBinding, stun.ClassSuccess, req.TxIDBytes())
	resp.AddXorAddress(stun.AttrXorMappedAddress, src)
	resp.AddString(stun.AttrSoftware, softwareName)
	resp.AddFingerprint()
	return resp
}

// errorResponse builds an ERROR-CODE response. When challenge is true REALM and
// a fresh NONCE are attached (used for 401 and 438).
func (s *Server) errorResponse(req *stun.Message, code int, reason string,
	challenge bool, txID []byte) *stun.Message {
	if txID == nil {
		txID = req.TxIDBytes()
	}
	resp := stun.New(req.Method(), stun.ClassError, txID)
	resp.AddErrorCode(code, reason)
	if challenge {
		resp.AddString(stun.AttrRealm, s.nonces.Realm())
		resp.AddString(stun.AttrNonce, s.nonces.Issue())
	}
	resp.AddString(stun.AttrSoftware, softwareName)
	resp.AddFingerprint()
	return resp
}

func (s *Server) successResponse(method uint16, txID []byte, key []byte) *stun.Message {
	resp := stun.New(method, stun.ClassSuccess, txID)
	resp.AddString(stun.AttrSoftware, softwareName)
	resp.AddIntegrity(key)
	resp.AddFingerprint()
	return resp
}

// authResult is the outcome of the long-term credential check.
type authResult struct {
	alloc *Allocation
	key   []byte
}

// authenticate performs the long-term credential exchange (RFC 5389 15.4).
// It returns an STUN error code (0 on success) to send to the client.
func (s *Server) authenticate(msg *stun.Message, src *net.UDPAddr,
	requireAlloc bool) (authResult, int) {
	nonce, _ := msg.String(stun.AttrNonce)
	username, hasUser := msg.String(stun.AttrUsername)
	realm, _ := msg.String(stun.AttrRealm)

	if nonce == "" || !hasUser {
		return authResult{}, stun.StatusUnauthenticated
	}

	if realm != s.nonces.Realm() {
		return authResult{}, stun.StatusUnauthenticated
	}

	key, ok := s.cfg.Credentials.Key(username, realm)
	if !ok || len(username) >= 512 {
		return authResult{}, stun.StatusWrongCredentials
	}

	if !msg.CheckIntegrity(key) {
		return authResult{}, stun.StatusWrongCredentials
	}

	// Nonce freshness is checked only after the request proved possession of the
	// long-term key, so an expired but otherwise valid request gets 438 with a
	// fresh nonce (RFC 5389 15.4, RFC 5766 4.3).
	if !s.nonces.Verify(nonce) {
		return authResult{}, stun.StatusStaleNonce
	}

	s.mu.Lock()
	alloc := s.allocations[s.clientKey(src)]
	s.mu.Unlock()
	if requireAlloc && alloc == nil {
		return authResult{}, stun.StatusAllocMismatch
	}
	if alloc != nil && alloc.username != username {
		return authResult{}, stun.StatusWrongCredentials
	}
	return authResult{alloc: alloc, key: key}, 0
}

func (s *Server) authError(req *stun.Message, code int) *stun.Message {
	switch code {
	case stun.StatusUnauthenticated:
		return s.errorResponse(req, code, "Unauthorized", true, nil)
	case stun.StatusStaleNonce:
		return s.errorResponse(req, code, "Stale Nonce", true, nil)
	case stun.StatusWrongCredentials:
		return s.errorResponse(req, code, "Wrong Credentials", false, nil)
	case stun.StatusAllocMismatch:
		return s.errorResponse(req, code, "Allocation Mismatch", false, nil)
	default:
		return s.errorResponse(req, code, "Error", false, nil)
	}
}

func (s *Server) handleAllocate(req *stun.Message, src *net.UDPAddr) *stun.Message {
	auth, errCode := s.authenticate(req, src, false)
	if errCode != 0 {
		return s.authError(req, errCode)
	}

	transport, ok := req.Uint32(stun.AttrRequestedTransport)
	if !ok {
		return s.errorResponse(req, stun.StatusBadRequest,
			"REQUESTED-TRANSPORT attribute missing", false, nil)
	}
	if byte(transport>>24) != udpProto {
		return s.errorResponse(req, stun.StatusUnsupportedTransport,
			"Only UDP transport is supported", false, nil)
	}

	requested, _ := req.Lifetime(stun.AttrLifetime)
	lifetime := s.cfg.DefaultLifetime
	if requested > 0 {
		lifetime = requested
		if lifetime > s.cfg.MaxLifetime {
			lifetime = s.cfg.MaxLifetime
		}
	}

	now := time.Now()

	// A repeat Allocate on an existing 5-tuple with the same transport acts as
	// a Refresh and returns the existing relay address (RFC 5766 section 6.2).
	// Non-UDP transports were rejected above with 442.
	if auth.alloc == nil {
		a, err := s.createAllocation(src, now, lifetime)
		if err != nil {
			return s.errorResponse(req, stun.StatusInsufficientCapacity,
				"Cannot allocate relay address", false, nil)
		}
		a.username = usernameFromRequest(req)
		s.installAllocation(src, a)
		auth.alloc = a
	} else {
		auth.alloc.refresh(now, lifetime)
	}

	resp := s.successResponse(stun.MethodAllocate, req.TxIDBytes(), auth.key)
	resp.AddXorAddress(stun.AttrXorMappedAddress, src)
	resp.AddXorAddress(stun.AttrXorRelayedAddress, s.relayAddress(auth.alloc))
	resp.AddLifetime(stun.AttrLifetime, lifetime)
	return resp
}

func usernameFromRequest(msg *stun.Message) string {
	u, _ := msg.String(stun.AttrUsername)
	return u
}

func (s *Server) handleRefresh(req *stun.Message, src *net.UDPAddr) *stun.Message {
	auth, errCode := s.authenticate(req, src, true)
	if errCode != 0 {
		return s.authError(req, errCode)
	}
	now := time.Now()

	if requested, ok := req.Lifetime(stun.AttrLifetime); ok && requested == 0 {
		s.removeAllocation(src)
		_ = auth.alloc.close()
		resp := s.successResponse(stun.MethodRefresh, req.TxIDBytes(), auth.key)
		resp.AddUint32(stun.AttrLifetime, 0)
		return resp
	}

	lifetime := s.cfg.DefaultLifetime
	if requested, ok := req.Lifetime(stun.AttrLifetime); ok && requested > 0 {
		lifetime = requested
		if lifetime > s.cfg.MaxLifetime {
			lifetime = s.cfg.MaxLifetime
		}
	}
	auth.alloc.refresh(now, lifetime)

	resp := s.successResponse(stun.MethodRefresh, req.TxIDBytes(), auth.key)
	resp.AddLifetime(stun.AttrLifetime, lifetime)
	return resp
}

func (s *Server) handleCreatePermission(req *stun.Message, src *net.UDPAddr) *stun.Message {
	auth, errCode := s.authenticate(req, src, true)
	if errCode != 0 {
		return s.authError(req, errCode)
	}

	peers := req.Peers()
	if len(peers) == 0 {
		return s.errorResponse(req, stun.StatusBadRequest,
			"XOR-PEER-ADDRESS attribute missing", false, nil)
	}

	now := time.Now()
	for _, peer := range peers {
		auth.alloc.ensurePermission(peer, now, s.cfg.PermissionTTL)
	}
	return s.successResponse(stun.MethodCreatePermission, req.TxIDBytes(), auth.key)
}

func (s *Server) handleChannelBind(req *stun.Message, src *net.UDPAddr) *stun.Message {
	auth, errCode := s.authenticate(req, src, true)
	if errCode != 0 {
		return s.authError(req, errCode)
	}

	number, err := req.ChannelNumber()
	if err != nil {
		return s.errorResponse(req, stun.StatusBadRequest,
			"CHANNEL-NUMBER attribute missing or invalid", false, nil)
	}

	// A ChannelBind carries exactly one XOR-PEER-ADDRESS.
	peers := req.Peers()
	if len(peers) != 1 {
		return s.errorResponse(req, stun.StatusBadRequest,
			"Exactly one XOR-PEER-ADDRESS is required", false, nil)
	}

	now := time.Now()
	if err := auth.alloc.bindChannel(number, peers[0], now, s.cfg.ChannelTTL); err != nil {
		reason := "Bad Request"
		switch err {
		case ErrChannelNumberRange:
			reason = "Channel Number Outside 0x4000-0x4FFF"
		case ErrChannelNumberBusy:
			reason = "Channel Number Bound to a Different Peer"
		case ErrPeerChannelBusy:
			reason = "Peer Bound to a Different Channel"
		}
		return s.errorResponse(req, stun.StatusBadRequest, reason, false, nil)
	}
	return s.successResponse(stun.MethodChannelBind, req.TxIDBytes(), auth.key)
}
