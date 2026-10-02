package turn

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// Server is a STUN/TURN UDP server.
type Server struct {
	config Config

	conn *net.UDPConn
	auth *authenticator

	mu          sync.Mutex
	allocations map[string]*Allocation

	closeOnce sync.Once
	closed    chan struct{}
	Started   chan struct{}
}

// NewServer creates a server with the given configuration.
func NewServer(cfg Config) *Server {
	return &Server{
		config:      cfg.withDefaults(),
		auth:        newAuthenticator(cfg),
		allocations: make(map[string]*Allocation),
		closed:      make(chan struct{}),
		Started:     make(chan struct{}),
	}
}

// ListenAndServe binds sockets and serves until the context is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", s.config.ListenAddress)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	close(s.Started)

	go s.readLoop()
	go s.sweepLoop(ctx, time.Second)

	<-ctx.Done()
	return s.Close()
}

// Close shuts the server down.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		for key, a := range s.allocations {
			a.close()
			delete(s.allocations, key)
		}
		s.mu.Unlock()
		if s.conn != nil {
			err = s.conn.Close()
		}
		close(s.closed)
	})
	return err
}

// LocalAddr returns the client-facing listener address.
func (s *Server) LocalAddr() *net.UDPAddr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr().(*net.UDPAddr)
}

func (s *Server) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		// Every datagram is handled independently so one bad client or
		// slow handler can never block the shared reader.
		go s.handleDatagram(data, src)
	}
}

func (s *Server) handleDatagram(data []byte, src *net.UDPAddr) {
	if stun.IsChannelData(data) {
		s.handleChannelData(data, src)
		return
	}
	msg, err := stun.Parse(data)
	if err != nil {
		return
	}
	s.handleMessage(data, msg, src)
}

func (s *Server) handleMessage(raw []byte, msg *stun.Message, src *net.UDPAddr) {
	switch msg.Method {
	case stun.MethodBinding:
		if msg.Class == stun.ClassRequest {
			s.handleBinding(msg, src)
		}
	case stun.MethodAllocate:
		if msg.Class == stun.ClassRequest {
			s.handleAllocate(raw, msg, src)
		}
	case stun.MethodRefresh, stun.MethodCreatePerm, stun.MethodChannelBind:
		if msg.Class != stun.ClassRequest {
			return
		}
		alloc, ok := s.allocationFor(src)
		if !ok {
			s.sendMethodError(msg.Method, src, msg.TransactionID, nil, CodeBadRequest, "No allocation exists")
			return
		}
		switch msg.Method {
		case stun.MethodRefresh:
			s.handleRefresh(raw, msg, alloc, src)
		case stun.MethodCreatePerm:
			s.handleCreatePermission(raw, msg, alloc, src)
		case stun.MethodChannelBind:
			s.handleChannelBind(raw, msg, alloc, src)
		}
	case stun.MethodSend:
		if msg.Class == stun.ClassIndication {
			if alloc, ok := s.allocationFor(src); ok {
				s.handleSendIndication(msg, alloc, src)
			}
		}
	}
}

func (s *Server) sweepLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.sweep(now)
		}
	}
}

func (s *Server) allocationFor(src *net.UDPAddr) (*Allocation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.allocations[src.String()]
	return a, ok
}

func (s *Server) removeAllocation(key string) {
	s.mu.Lock()
	a, ok := s.allocations[key]
	if ok {
		delete(s.allocations, key)
	}
	s.mu.Unlock()
	if ok {
		a.close()
	}
}

func (s *Server) sweep(now time.Time) {
	s.mu.Lock()
	var expired []string
	for key, a := range s.allocations {
		a.mu.Lock()
		dead := !now.Before(a.expiresAt)
		a.mu.Unlock()
		if dead {
			expired = append(expired, key)
			continue
		}
		a.mu.Lock()
		a.cleanupLocked(now)
		a.mu.Unlock()
	}
	s.mu.Unlock()
	for _, key := range expired {
		s.removeAllocation(key)
	}
}
