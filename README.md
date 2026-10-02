# turn-relay-server-go

A locally runnable STUN/TURN relay server implemented in Go. Clients and
peers communicate with the server over UDP on loopback addresses, following
RFC 5389 (STUN) and RFC 5766 (TURN, UDP relay).

## Features

- STUN `Binding` request/response with `XOR-MAPPED-ADDRESS`.
- STUN message integrity: `FINGERPRINT` and long-term-credential
  `MESSAGE-INTEGRITY` (HMAC-SHA1).
- TURN `Allocate` bound to the client source address, returning
  `XOR-RELAYED-ADDRESS`, `XOR-MAPPED-ADDRESS` and `LIFETIME`.
- `Refresh` renewal, refresh with lifetime `0` (explicit delete) and
  automatic expiry/reaping.
- Long-term authentication for `Allocate`, `Refresh`, `CreatePermission`
  and `ChannelBind`:
  - Unauthenticated requests get `401 Unauthorized` with `REALM` and `NONCE`.
  - Retries carrying valid username/realm/nonce and a correct
    `MESSAGE-INTEGRITY` succeed.
  - Expired nonces get `438 Stale Nonce` with a fresh nonce.
- Explicit per-peer authorization through `CreatePermission`; data to or
  from unauthorized peers is dropped. Permissions and channel bindings
  expire and are reaped (binding a channel installs the matching
  permission, per RFC 5766).
- Both relay paths:
  - `Send` / `Data` indications, carrying `XOR-PEER-ADDRESS` and `DATA`.
  - `ChannelBind` + bidirectional `ChannelData`, routed by channel number
    (`0x4000..0x7FFF`). Writes to a client are serialized, so frames on the
    same channel keep ordering.
- Per-allocation bounded send queue. A slow TURN client only drops its own
    datagrams; peers, the shared reader and other allocations are not
    blocked. Each datagram is handled in its own goroutine.
- Distinguishable error codes for malformed input, allocation conflicts,
    channel conflicts, unsupported transport and stale credentials.

## Running

```sh
go run ./cmd/turn-server \
  -listen 127.0.0.1:3478 \
  -relay 127.0.0.1:0 \
  -realm turn.local \
  -user user:pass
```

The listener is the STUN/TURN endpoint clients send to. Each allocation
binds a separate UDP socket on the relay host (the port is picked by the
kernel and returned as `XOR-RELAYED-ADDRESS`). Peers exchange data with
that relay address. Multiple users can be passed as a comma-separated list,
e.g. `-user alice:secret,bob:hunter2`.

## Configuration

CLI flags and their defaults (also the zero values in `turn.Config`):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `127.0.0.1:3478` | Client-facing UDP endpoint. |
| `-relay` | `127.0.0.1:0` | Host used for per-allocation relay sockets. |
| `-realm` | `turn.local` | Authentication realm. |
| `-user` | `test:test` | Long-term credentials `username:password`. |

Programmatic tunables in `internal/turn.Config`:

| Field | Default | Meaning |
| --- | --- | --- |
| `MaxLifetime` | `1h` | Upper bound for allocation lifetime. |
| `DefaultLifetime` | `10m` | Lifetime used when none is requested. |
| `PermissionLifetime` | `5m` | Permission and channel-binding lifetime. |
| `NonceLifetime` | `10m` | Validity of issued nonces. |
| `SendQueueSize` | `1024` | Per-allocation queued datagrams before drops. |

## Protocol exchange

Authenticated methods use the standard challenge/response flow:

1. Client sends `Allocate` (optionally with no credentials).
2. Server answers `401 Unauthorized` containing `REALM` and `NONCE`.
3. Client derives the key
   `HMAC-SHA1 key = MD5(username:realm:password)` and retries with
   `USERNAME`, `REALM`, `NONCE`, `MESSAGE-INTEGRITY` and `FINGERPRINT`.
4. Server validates the nonce and HMAC and returns the success response.
5. Client creates permissions with `CreatePermission`, then exchanges data
   via `Send` indications or bound channels. `Refresh` renews the
   allocation before it expires.

Binding requests and `Send` indications are not authenticated, but relay
data still requires a live permission. Responses to authenticated requests
are integrity-protected with `MESSAGE-INTEGRITY` and `FINGERPRINT`.

## Error codes

| Code | Reason | Trigger |
| --- | --- | --- |
| `400` | Bad Request | Malformed attributes, out-of-range/conflicting channel numbers. |
| `401` | Unauthorized | Missing credentials or invalid `MESSAGE-INTEGRITY`; includes realm/nonce. |
| `437` | Allocation Mismatch | A second `Allocate` from the same client address. |
| `438` | Stale Nonce | The supplied nonce expired; a fresh nonce is returned. |
| `442` | Unsupported Transport Protocol | `REQUESTED-TRANSPORT` is not UDP (17). |
| `508` | Insufficient Capacity | A relay socket could not be allocated. |

## Security boundaries

- Credentials are static long-term pairs; there is no user database, TURN
  REST API short-term passwords, OAuth or DANE.
- Nonces are random and time-limited; replaying an expired nonce yields
  `438`. There is no per-username nonce binding: any valid credential pair
  in the configured realm may use an issued nonce, matching basic RFC 5389
  long-term auth.
- Relay traffic is only accepted after an explicit `CreatePermission` (or
  `ChannelBind`) for the peer IP, and permissions/channels expire. Peer
  identity is the IP/port of the UDP datagram.
- All sockets bind loopback (`127.0.0.1`) by default; this implementation
  is intended for local development/testing, not exposure to untrusted
  networks.
- Only IPv4/UDP is supported: no TCP, TLS, DTLS, IPv6, ALPN, mobility or
  `DONT-FRAGMENT`.
- Resource limits are per-allocation queue size and allocation lifetime;
  there is no global rate limiting or quota enforcement beyond rejecting a
  duplicate allocation per client address.
- Malformed datagrams are ignored without affecting other clients; they do
  not consume allocation state.

## Tests

```sh
go test ./...
go test ./... -race -count=3
```

Coverage includes STUN encode/decode, XOR addresses, FINGERPRINT and
MESSAGE-INTEGRITY, ChannelData framing, binding, the 401/438 challenge
flow, allocation conflict and unsupported transport, refresh/expiry,
permissions (including expiry drops), indication and channel relay in both
directions with ordering, channel conflicts, bounded queue drop behavior,
and concurrent-client isolation.
