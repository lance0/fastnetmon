# rustbgpd integration

FastNetMon can announce blackhole routes through [rustbgpd](https://github.com/lance0/rustbgpd), a BGP daemon with a gRPC API. The `rustbgpd` action calls rustbgpd's `InjectionService` directly: `AddPath` on ban and `DeletePath` on unban. Unlike the GoBGP action, it sends typed fields (prefix, next hop, communities) instead of encoded BGP attributes, and it needs no GoBGP daemon.

The action handles IPv4 hosts, IPv4 customer subnets and IPv6 hosts, each with one community and next hop, like the GoBGP action. It can run at the same time as the GoBGP or ExaBGP actions.

It was tested with rustbgpd 0.79.0. Earlier rustbgpd releases reject the `0.0.0.0` and `::` next hops this action uses by default.

## Build

The action is built when gRPC support is built (`ENABLE_GOBGP_SUPPORT`, on by default). To leave it out, configure with `-DENABLE_RUSTBGPD_SUPPORT=OFF`.

The action uses a reduced copy of rustbgpd's API definition, `src/rustbgpd_client/rustbgpd_injection.proto`. Its header names the rustbgpd release it was copied from and that file's SHA-256.

## FastNetMon configuration

```
rustbgpd = on

# rustbgpd's default owner-only Unix socket
rustbgpd_target = unix:///var/lib/rustbgpd/grpc.sock

# 0.0.0.0 and :: mean next hop self: rustbgpd uses its own address on each BGP session
rustbgpd_next_hop_host_ipv4 = 0.0.0.0
rustbgpd_next_hop_subnet_ipv4 = 0.0.0.0
rustbgpd_next_hop_host_ipv6 = ::

rustbgpd_announce_host = on
rustbgpd_announce_whole_subnet = off
rustbgpd_announce_host_ipv6 = on

rustbgpd_community_host = 65535:666
rustbgpd_community_subnet = 65535:666
rustbgpd_community_host_ipv6 = 65535:666
```

| Option | Default | Meaning |
|---|---|---|
| `rustbgpd` | `off` | Enable the action |
| `rustbgpd_target` | `unix:///var/lib/rustbgpd/grpc.sock` | rustbgpd gRPC endpoint: `unix:///path`, or a loopback address and port such as `127.0.0.1:50051` |
| `rustbgpd_token_file` | empty | File with the bearer token for a TCP listener; sent as `authorization: Bearer <token>` on every call |
| `rustbgpd_next_hop_host_ipv4` | `0.0.0.0` | Next hop for IPv4 host announces; `0.0.0.0` means next hop self |
| `rustbgpd_next_hop_subnet_ipv4` | `0.0.0.0` | Next hop for IPv4 subnet announces |
| `rustbgpd_next_hop_host_ipv6` | `::` | Next hop for IPv6 host announces; `::` means next hop self |
| `rustbgpd_announce_host` | `on` | Announce the attacked IPv4 address as /32 |
| `rustbgpd_announce_whole_subnet` | `off` | Announce the customer network of the attacked IPv4 address |
| `rustbgpd_announce_host_ipv6` | `on` | Announce the attacked IPv6 address as /128 |
| `rustbgpd_community_host`, `rustbgpd_community_subnet`, `rustbgpd_community_host_ipv6` | `65535:666` | Community in `ASN:value` form; `65535:666` is BLACKHOLE (RFC 7999) |
| `rustbgpd_reconcile_interval` | `30` | Seconds between passes which announce all active bans again |
| `rustbgpd_lease` | `off` | Announce under an injection lease, see below |
| `rustbgpd_lease_owner` | `fastnetmon` | Lease owner name, 1-64 characters of `A-Z a-z 0-9 . _ -` |
| `rustbgpd_lease_time` | `30` | Lease time in seconds, 5-3600 |

FastNetMon does not start the action when an option is invalid, and logs which one.

### Connecting to rustbgpd

rustbgpd accepts plaintext gRPC only on its owner-only Unix socket or on a TCP listener with a bearer token. The action allows only a Unix socket or a loopback address, so the token never leaves the host.

- **Unix socket** (default). rustbgpd authorizes clients of its owner-only socket as its local operator; no token is needed. FastNetMon must be able to open the socket: run it as rustbgpd's user, or as root.
- **Loopback TCP with token.** Configure the listener in rustbgpd and map its principal to the `operator` role, which route injection requires:

  ```toml
  [global.telemetry.grpc_tcp]
  address = "127.0.0.1:50051"
  token_file = "/etc/rustbgpd/grpc.token"
  principal = "fastnetmon"

  [security.grpc.roles]
  "fastnetmon" = "operator"
  ```

  Then in FastNetMon:

  ```
  rustbgpd_target = 127.0.0.1:50051
  rustbgpd_token_file = /etc/rustbgpd/grpc.token
  ```

## rustbgpd configuration

rustbgpd advertises injected routes like locally originated routes, subject to each neighbor's export policy. This policy sends only injected /32 and /128 routes which carry BLACKHOLE:

```toml
[policy.definitions.rtbh-only]
default_action = "deny"
[[policy.definitions.rtbh-only.statements]]
action = "permit"
match_route_type = "local"
prefix = "0.0.0.0/0"
ge = 32
match_community = ["BLACKHOLE"]
[[policy.definitions.rtbh-only.statements]]
action = "permit"
match_route_type = "local"
prefix = "::/0"
ge = 128
match_community = ["BLACKHOLE"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast"]
# Needed for IPv6 next hop self on an IPv4 session
local_ipv6_nexthop = "2001:db8:126::1"
export_policy_chain = ["rtbh-only"]
```

Add statements for other prefix lengths and communities if you enable `rustbgpd_announce_whole_subnet` or use other communities.

## Behaviour

- Each call is checked. The log shows the outcome rustbgpd returns: `PATH_INJECT_OUTCOME_CREATED`, `REPLACED` or `UNCHANGED` for an announce, `PATH_DELETE_OUTCOME_DELETED` or `NOT_PRESENT` for a withdrawal, or the gRPC error.
- Withdrawals set `allow_missing`, so withdrawing a route rustbgpd no longer has succeeds.
- rustbgpd keeps injected routes in memory only. The action keeps its list of active bans and announces all of them again:
  - as soon as rustbgpd answers after its liveness probe failed, for example after a rustbgpd restart (the action probes every 0.5 seconds);
  - after a call failed because rustbgpd was unreachable;
  - every `rustbgpd_reconcile_interval` seconds.

  A withdrawal which failed is retried the same way.
- On a planned rustbgpd restart, BGP peers with Graceful Restart keep the blackholes as stale routes. rustbgpd sends End-of-RIB soon after the session comes back, and the action announces the bans again shortly after rustbgpd's API answers. A short gap between the two is possible, so a peer may drop a blackhole for a moment. A restart faster than one probe interval is caught by the periodic pass instead.
- Ban lists are not persistent in FastNetMon either. If FastNetMon stops, its bans stay in rustbgpd until they are withdrawn by hand (`rbgp rib delete <prefix>`) or until rustbgpd restarts, unless leases are on.

## Leases (experimental)

With `rustbgpd_lease = on` the action uses `AddLeasedPath` instead of `AddPath`, all under one owner (`rustbgpd_lease_owner`), and renews the lease every third of `rustbgpd_lease_time`. If FastNetMon stops renewing, rustbgpd withdraws all of the owner's bans when the lease expires. When rustbgpd refuses a renewal, the action announces all active bans again under a new lease.

The lease calls (`AddLeasedPath`, `RenewLease`) are not part of rustbgpd's stable v1 API in rustbgpd 0.79.0 and may change in later releases.

Limitations:

- A restarted FastNetMon uses the same owner and joins the existing lease. Bans the previous process held and the new one does not know about stay announced while the lease is renewed. Remove them with `rbgp rib delete <prefix> --override-owner`.
- A route added without a lease cannot be taken over by a leased add, and the other way round: rustbgpd answers `FAILED_PRECONDITION` and the action logs the prefix. Delete such routes once when you switch leases on or off.
