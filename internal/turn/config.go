package turn

import "time"

// Config holds server configuration.
type Config struct {
	// ListenAddress is the UDP address clients connect to (TURN/STUN).
	ListenAddress string
	// RelayAddress is the local address used for relayed sockets.
	RelayAddress string
	// Realm used for long-term authentication.
	Realm string
	// Credentials maps username to password.
	Credentials map[string]string

	// MaxLifetime bounds the LIFETIME granted to clients.
	MaxLifetime time.Duration
	// DefaultLifetime is used when clients request no lifetime.
	DefaultLifetime time.Duration
	// PermissionLifetime is the lifetime of permissions and channels.
	PermissionLifetime time.Duration
	// NonceLifetime bounds the validity of issued nonces.
	NonceLifetime time.Duration

	// SendQueueSize bounds per-allocation queued datagrams.
	SendQueueSize int
}

// DefaultConfig returns a config usable on loopback.
func DefaultConfig() Config {
	return Config{
		ListenAddress:      "127.0.0.1:3478",
		RelayAddress:       "127.0.0.1:0",
		Realm:              "turn.local",
		Credentials:        map[string]string{"test": "test"},
		MaxLifetime:        3600 * time.Second,
		DefaultLifetime:    600 * time.Second,
		PermissionLifetime: 300 * time.Second,
		NonceLifetime:      600 * time.Second,
		SendQueueSize:      1024,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.ListenAddress == "" {
		c.ListenAddress = d.ListenAddress
	}
	if c.RelayAddress == "" {
		c.RelayAddress = d.RelayAddress
	}
	if c.Realm == "" {
		c.Realm = d.Realm
	}
	if c.Credentials == nil {
		c.Credentials = d.Credentials
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = d.MaxLifetime
	}
	if c.DefaultLifetime <= 0 {
		c.DefaultLifetime = d.DefaultLifetime
	}
	if c.PermissionLifetime <= 0 {
		c.PermissionLifetime = d.PermissionLifetime
	}
	if c.NonceLifetime <= 0 {
		c.NonceLifetime = d.NonceLifetime
	}
	if c.SendQueueSize <= 0 {
		c.SendQueueSize = d.SendQueueSize
	}
	return c
}
