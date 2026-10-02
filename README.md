# turn-relay-server-go

一个可在本地直接运行的 **STUN / TURN** 中继服务器（Go 实现），让受限网络后的
客户端通过服务器中继与对端（peer）交换 UDP 数据。默认只监听回环地址，
行为遵循：

- STUN：[RFC 5389](https://www.rfc-editor.org/rfc/rfc5389)
- TURN：[RFC 5766](https://www.rfc-editor.org/rfc/rfc5766)（仅 UDP 中继）

## 功能

- **Binding**：返回 `XOR-MAPPED-ADDRESS`，响应携带 `FINGERPRINT`。
- **长期凭据认证**：`Allocate` / `Refresh` / `CreatePermission` /
  `ChannelBind` 未认证时返回 `401` 并携带 `REALM` + `NONCE`；客户端用
  `USERNAME` / `REALM` / `NONCE` 重算 `MESSAGE-INTEGRITY`（HMAC-SHA1，
  密钥为 `MD5(username:realm:password)`）后重试成功。`NONCE` 带签名与
  过期时间，过期返回 `438 Stale Nonce` 并重新下发材料。
- **Allocate**：与客户端来源地址（5-tuple 的主机部分）绑定，返回
  `XOR-RELAY-ADDRESS` 与 `LIFETIME`；同一 5-tuple 的重复 Allocate 等价于
  Refresh；支持 `Refresh` 显式续期（`LIFETIME=0` 删除分配）与后台过期回收。
- **权限**：必须通过 `CreatePermission` 显式授权 peer 才可收发数据；
  未授权 peer 的数据在两个方向上都被丢弃；权限可续期并在 TTL 后回收。
  成功的 ChannelBind 同时刷新对应 peer 的权限。
- **两种中继方式**：
  - `Send` / `Data` indication（无 MI，靠来源地址绑定 + 权限授权）；
  - `ChannelData`：`ChannelBind` 后按通道号路由，peer→client 方向优先以
    ChannelData 封装。同一分配的所有下行帧由**单个 goroutine** 串行写出，
    保证同一通道数据有序。
- **隔离与有界缓冲**：每个分配独立 relay socket 与状态；慢速接收方不会
  阻塞服务器或其他分配，每个分配有固定深度的下行队列，满时丢新包。

## 快速开始

```bash
go build ./...
go run ./cmd/turn-server -user alice:pencil
# 监听 127.0.0.1:3478（默认）
```

可重复或用逗号配置多个账号：

```bash
go run ./cmd/turn-server -user alice:pencil,bob:hunter2
```

### 协议交互

```
客户端                          服务器
  │ Allocate                       │
  │───────────────────────────────▶│
  │ 401 + REALM, NONCE             │
  │◀───────────────────────────────│
  │ Allocate + USERNAME/REALM/NONCE│
  │          + MESSAGE-INTEGRITY   │
  │───────────────────────────────▶│
  │ 200 + XOR-MAPPED-ADDRESS       │
  │     XOR-RELAY-ADDRESS,LIFETIME │
  │◀───────────────────────────────│
  │ CreatePermission (peer) + MI   │
  │───────────────▶│ 200           │
  │ Send indication (XOR-PEER,DATA)│──▶ peer
  │                                │◀── peer
  │ Data indication (XOR-PEER,DATA)│
  │◀───────────────────────────────│
  │ ChannelBind (NUMBER, XOR-PEER) │
  │───────────────▶│ 200           │
  │ ChannelData #N ───────────────▶│──▶ peer
  │                                │◀── peer
  │ ChannelData #N                 │
  │◀───────────────────────────────│
```

## 配置项

| 标志 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `127.0.0.1:3478` | 客户端 UDP 监听地址 |
| `-realm` | `turn.local` | 认证 realm |
| `-public-ip` | `127.0.0.1` | `XOR-RELAY-ADDRESS` 中通告的 IP |
| `-user` | 空 | `username:password`，逗号分隔多个 |
| `-lifetime` | `10m` | 默认分配寿命 |
| `-max-lifetime` | `1h` | 客户端可申请的最大分配寿命 |
| `-permission-ttl` | `5m` | 权限寿命（RFC 5766 规定 300s） |
| `-channel-ttl` | `10m` | 通道绑定寿命（RFC 5766 规定 600s） |
| `-nonce-ttl` | `10m` | 认证 nonce 有效期 |
| `-queue` | `256` | 单分配下行队列深度（有界） |

## 错误码

| 码 | 触发场景 |
| --- | --- |
| `400 Bad Request` | 属性缺失/非法、通道号越界（非 `0x4000–0x4FFF`）、通道号/peer 冲突（reason 可区分） |
| `401 Unauthenticated` | 缺少认证材料或 realm 不符；携带新的 `REALM`/`NONCE` |
| `420 Unknown Attribute` | 未知关键属性（预留） |
| `437 Allocation Mismatch` | 未分配即调用 `Refresh`/`CreatePermission`/`ChannelBind` |
| `438 Stale Nonce` | nonce 过期/无效（签名校验在 HMAC 通过后进行）；携带新 nonce |
| `441 Wrong Credentials` | 用户不存在或 `MESSAGE-INTEGRITY` 校验失败 |
| `442 Unsupported Transport` | `REQUESTED-TRANSPORT` 非 UDP(17) |
| `508 Insufficient Capacity` | 无法再绑定 relay 地址 |

畸形 STUN 数据报与来自未绑定通道号的 ChannelData 一律静默丢弃，不影响
其他客户端。

## 安全边界

- **默认仅回环监听**：不做鉴权之外的访问控制，直接暴露到公网前需自行评估
  滥用/放大风险，并通过 `-addr`、防火墙限定来源。
- **认证范围**：`Binding` 按 RFC 无需认证；indication 不携带 MI，其合法性
  来自来源地址与已建立分配的绑定以及 peer 权限。
- **权限模型**：授权以 `IP:port` 为粒度；NAT 后端口复用需自行评估。
- **抗慢速/抗阻塞**：单分配队列有界、满即丢；relay 读循环容忍异步 ICMP
  错误，单个不可达 peer 不会拖垮其他 peer。
- **凭据存储**：内置静态用户名/密码表（`turn.StaticCredentials`）；生产
  环境可实现 `turn.CredentialStore` 接入短期凭据（如时间限制的 TURN REST
  API）。
- 本实现用于本地开发/测试与教学，未实现 TLS/DTLS、TCP/TLS 传输与带宽计量。

## 测试

```bash
go test ./...
go test -race ./...
```

覆盖：Binding（含 FINGERPRINT）、401/438/441/442/437/400 错误码、Allocate
与重复 Allocate、Refresh 续期与 `LIFETIME=0`、分配/权限/通道过期回收、
CreatePermission 授权前后两个方向的放行与丢弃、Send indication 与
ChannelData 双向转发、通道号冲突、50 包顺序保持、多客户端不串线、
慢速客户端不阻塞且队列不超界、畸形数据报忽略。

## 代码结构

- `stun/`：RFC 5389 消息编解码（属性、XOR 地址、ERROR-CODE、
  MESSAGE-INTEGRITY、FINGERPRINT）。
- `turn/auth.go`：长期凭据密钥与签名 nonce。
- `turn/allocation.go`：分配、权限、通道绑定的状态与过期回收。
- `turn/relay.go`：relay socket 接收循环与有界下行队列。
- `turn/channeldata.go`：ChannelData 帧编解码。
- `turn/handler.go`：请求分发、认证握手、STUN/TURN 方法处理。
- `turn/relay_control.go` / `turn/data_plane.go`：分配生命周期与
  indication / ChannelData 数据面。
- `cmd/turn-server/`：命令行入口。
