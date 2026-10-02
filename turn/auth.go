package turn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// CredentialStore resolves the long-term STUN key (RFC 5389 15.4) for a user.
type CredentialStore interface {
	Key(username, realm string) ([]byte, bool)
}

// StaticCredentials maps usernames to cleartext passwords.
type StaticCredentials map[string]string

// Key implements CredentialStore.
func (s StaticCredentials) Key(username, realm string) ([]byte, bool) {
	password, ok := s[username]
	if !ok {
		return nil, false
	}
	return LongTermKey(username, realm, password), true
}

// LongTermKey derives MD5(username:realm:password).
func LongTermKey(username, realm, password string) []byte {
	h := md5.New()
	h.Write([]byte(username + ":" + realm + ":" + password))
	return h.Sum(nil)
}

// NonceManager issues and validates signed, time-limited server nonces.
type NonceManager struct {
	realm  string
	ttl    time.Duration
	secret []byte
	now    func() time.Time
}

// NewNonceManager creates a NonceManager for the given realm.
func NewNonceManager(realm string, ttl time.Duration) *NonceManager {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &NonceManager{realm: realm, ttl: ttl, secret: secret, now: time.Now}
}

// Realm returns the authentication realm.
func (m *NonceManager) Realm() string { return m.realm }

// Issue returns a fresh signed nonce.
func (m *NonceManager) Issue() string {
	return m.sign(m.now().Add(m.ttl))
}

// Verify reports whether the nonce is well-formed and unexpired.
func (m *NonceManager) Verify(nonce string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	if !hmac.Equal(raw[8:], m.macFor(raw[:8])) {
		return false
	}
	expiry := int64(binary.BigEndian.Uint64(raw[:8]))
	return m.now().UnixNano() <= expiry
}

func (m *NonceManager) sign(expiry time.Time) string {
	raw := make([]byte, 8+sha256.Size)
	binary.BigEndian.PutUint64(raw[:8], uint64(expiry.UnixNano()))
	copy(raw[8:], m.macFor(raw[:8]))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (m *NonceManager) macFor(expiryBytes []byte) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte("turn-nonce"))
	mac.Write(expiryBytes)
	return mac.Sum(nil)
}
