package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"github.com/guoyyit/turn-relay-server-go/internal/turn"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:3478", "client-facing UDP listen address")
	relay := flag.String("relay", "127.0.0.1:0", "host used when binding per-allocation relay sockets")
	realm := flag.String("realm", "turn.local", "authentication realm")
	user := flag.String("user", "test:test", "long-term credentials as username:password (repeatable comma list allowed)")
	flag.Parse()

	creds := map[string]string{}
	for _, pair := range strings.Split(*user, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
		if len(parts) == 2 {
			creds[parts[0]] = parts[1]
		}
	}

	cfg := turn.DefaultConfig()
	cfg.ListenAddress = *listen
	cfg.RelayAddress = *relay
	cfg.Realm = *realm
	cfg.Credentials = creds

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := turn.NewServer(cfg)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx)
	}()
	select {
	case <-srv.Started:
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
		return
	}
	log.Printf("STUN/TURN server listening on udp://%s (relay sockets on %s, realm %s)",
		srv.LocalAddr(), *relay, *realm)
	<-ctx.Done()
	_ = srv.Close()
	log.Printf("server stopped")
}
