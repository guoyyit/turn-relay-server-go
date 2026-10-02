// Command turn-server runs a STUN/TURN relay server on the loopback address.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guoyyit/turn-relay-server-go/turn"
)

func parseFlags() turn.Config {
	var (
		listen      = flag.String("addr", "127.0.0.1:3478", "client-facing UDP listen address")
		realm       = flag.String("realm", "turn.local", "authentication realm")
		publicIP    = flag.String("public-ip", "127.0.0.1", "IP advertised in XOR-RELAY-ADDRESS")
		users       = flag.String("user", "", "long-term credential, repeat or comma separate username:password")
		defaultLife = flag.Duration("lifetime", 10*time.Minute, "default allocation lifetime")
		maxLife     = flag.Duration("max-lifetime", time.Hour, "maximum allocation lifetime")
		permTTL     = flag.Duration("permission-ttl", 5*time.Minute, "permission lifetime")
		channelTTL  = flag.Duration("channel-ttl", 10*time.Minute, "channel binding lifetime")
		nonceTTL    = flag.Duration("nonce-ttl", 10*time.Minute, "authentication nonce lifetime")
		queueLen    = flag.Int("queue", 256, "per-allocation egress queue depth")
	)
	flag.Parse()

	creds := turn.StaticCredentials{}
	for _, item := range strings.Split(*users, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			log.Fatalf("invalid -user credential %q, want username:password", item)
		}
		creds[parts[0]] = parts[1]
	}

	return turn.Config{
		ListenAddr:      *listen,
		Realm:           *realm,
		PublicIP:        *publicIP,
		DefaultLifetime: *defaultLife,
		MaxLifetime:     *maxLife,
		PermissionTTL:   *permTTL,
		ChannelTTL:      *channelTTL,
		NonceTTL:        *nonceTTL,
		EgressQueueLen:  *queueLen,
		Credentials:     creds,
	}
}

func main() {
	srv := turn.New(parseFlags())
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down")
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
