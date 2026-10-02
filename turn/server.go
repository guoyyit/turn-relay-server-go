// Package turn implements a UDP TURN relay server (RFC 5766) with STUN
// binding support (RFC 5389).
package turn

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/guoyyit/turn-relay-server-go/stun"
)

const (
	defaultLifetime    = 10 * time.Minute
	maxLifetime        = 1 * time.Hour
	defaultNonceTTL    = 10 * time.Minute
	defaultEgressDepth = 256
	softwareName       = "turn-relay-server-go/1.0"
	maxMessageSize     = 65535
	reaperInterval     = 30 * time.Second
	udpProto           = 17
)

// Config configures a Server.
type Config struct {
	ListenAddr      string
	Realm           string
	PublicIP        string
	DefaultLifetime time.Duration
	MaxLifetime     time.Duration
	PermissionTTL   time.Duration
	ChannelTTL      time.Duration
	NonceTTL        time.Duration
	EgressQueueLen  int
	Credentials     CredentialStore
}

// Server is a STUN/TURN server listening on a single UDP socket.
type Server struct {
	cfg    Config
	nonces *NonceManager

	mu          sync.Mutex
	conn        *net.UDPConn
	allocations map[string]*Allocation
	closed      bool

	wg      sync.WaitGroup
	closeMu sync.Mutex
	done    chan struct{}
}

// New creates a server from cfg.
func New(cfg Config) *Server {
	if cfg.Realm == "" {
		cfg.Realm = "turn.local"
	}
	if cfg.DefaultLifetime <= 0 {
		cfg.DefaultLifetime = defaultLifetime
	}
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = maxLifetime
	}
	if cfg.PermissionTTL <= 0 {
		cfg.PermissionTTL = permissionTTL
	}
	if cfg.ChannelTTL <= 0 {
		cfg.ChannelTTL = channelTTL
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = defaultNonceTTL
	}
	if cfg.EgressQueueLen <= 0 {
		cfg.EgressQueueLen = defaultEgressDepth
	}
	if cfg.Credentials == nil {
		cfg.Credentials = StaticCredentials{}
	}
	return &Server{
		cfg:         cfg,
		nonces:      NewNonceManager(cfg.Realm, cfg.NonceTTL),
		allocations: make(map[string]*Allocation),
		done:        make(chan struct{}),
	}
}

// ListenAndServe binds the configured UDP address and serves requests.
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp4", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	return s.Serve(conn)
}

// Serve processes STUN/TURN traffic on an already bound connection.
func (s *Server) Serve(conn *net.UDPConn) error {
	s.closeMu.Lock()
	s.mu.Lock()
	if s.conn != nil {
		s.mu.Unlock()
		return errors.New("turn: server already serving")
	}
	s.conn = conn
	s.mu.Unlock()
	s.closeMu.Unlock()

	s.wg.Add(2)
	go s.readLoop()
	go s.reaperLoop()
	s.wg.Wait()

	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	return nil
}

// LocalAddr returns the client-facing listen address.
func (s *Server) LocalAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr().(*net.UDPAddr)
}

// Close stops the server and releases all allocations.
func (s *Server) Close() error {
	s.closeMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	allocs := s.allocations
	s.allocations = make(map[string]*Allocation)
	s.mu.Unlock()

	for _, a := range allocs {
		_ = a.close()
	}
	close(s.done)
	var err error
	if conn != nil {
		err = conn.Close()
	}
	s.closeMu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, maxMessageSize)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handleDatagram(pkt, addr)
	}
}

func (s *Server) reaperLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapExpired(time.Now())
		case <-s.done:
			return
		}
	}
}

func (s *Server) handleDatagram(pkt []byte, src *net.UDPAddr) {
	if IsChannelData(pkt) {
		s.handleChannelData(pkt, src)
		return
	}
	msg, err := stun.Parse(pkt)
	if err != nil {
		// Malformed datagrams from clients are ignored (RFC 5389 section 7.3.1).
		return
	}
	switch msg.Class() {
	case stun.ClassRequest:
		resp := s.handleRequest(msg, src)
		if resp != nil {
			s.sendToClient(src, resp)
		}
	case stun.ClassIndication:
		s.handleIndication(msg, src)
	}
}

func (s *Server) sendToClient(dst *net.UDPAddr, msg *stun.Message) {
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(b, dst)
}

func (s *Server) clientKey(addr *net.UDPAddr) string {
	return addr.String()
}

// reapExpired closes allocations past their lifetime.
func (s *Server) reapExpired(now time.Time) {
	var dead []*Allocation
	s.mu.Lock()
	for key, a := range s.allocations {
		if a.expired(now) {
			dead = append(dead, a)
			delete(s.allocations, key)
		}
	}
	s.mu.Unlock()
	for _, a := range dead {
		_ = a.close()
	}
}
