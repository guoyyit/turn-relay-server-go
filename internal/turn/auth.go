package turn

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/guoyyit/turn-relay-server-go/internal/stun"
)

// nonceEntry tracks an issued authentication nonce.
type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// authenticator manages nonces and long-term credentials.
type authenticator struct {
	mu     sync.Mutex
	config Config
	nonces map[string]nonceEntry
}

func newAuthenticator(cfg Config) *authenticator {
	return &authenticator{
		config: cfg.withDefaults(),
		nonces: make(map[string]nonceEntry),
	}
}

// issueNonce creates a fresh nonce.
func (a *authenticator) issueNonce() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	n := hex.EncodeToString(raw[:])
	a.mu.Lock()
	a.nonces[n] = nonceEntry{nonce: n, expiresAt: time.Now().Add(a.config.NonceLifetime)}
	a.mu.Unlock()
	return n
}

// validate checks the nonce and credentials, returning the HMAC key.
func (a *authenticator) validate(nonce, username string) (key []byte, stale bool, ok bool) {
	a.mu.Lock()
	entry, exists := a.nonces[nonce]
	a.mu.Unlock()
	if !exists {
		// Unknown nonces are treated like missing credentials rather than
		// stale; the client must restart the 401 exchange.
		return nil, false, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, true, false
	}
	password, found := a.config.Credentials[username]
	if !found {
		return nil, false, false
	}
	return stun.LongTermKey(username, a.config.Realm, password), false, true
}

// realm exposes the configured realm.
func (a *authenticator) realm() string {
	return a.config.Realm
}
