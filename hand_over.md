# Handover: udp2raw Integration into tinyfecVPN

## Goal
Integrate udp2raw's fake TCP transport layer directly into tinyfecVPN so that `--raw-mode 1` replaces the two-process setup (standalone udp2raw + tinyvpn via localhost).

## What Works
- **Localhost test** (on .110): Full handshake + FEC data exchange confirmed via tcpdump
- **Original udp2raw binary** compiled from the same submodule: Works cross-machine (.104 → .110) with XOR + auth_simple config
- **Server side of our integration**: Reaches `SERVER_READY` cross-machine — SYN-ACK and both handshake stages complete on the server

## What Doesn't Work
- **Cross-machine client**: Client gets to `client_handshake1` (SYN-ACK received) but never progresses to `handshake2`. The client DOES receive the 89-byte BARE handshake reply from the server (visible in CLI_RAW hex dump), but `recv_bare()` fails on it. Error: `auth_verify failed`.

## Configuration
- `cipher_mode = cipher_xor`, `auth_mode = auth_simple`, `disable_anti_replay = 1`
- No iptables DROP rule currently (it was removed; the original udp2raw works without it)
- Password: `testkey` → `normal_key` = `6fc5806cf2f8f04f39d2248621cbb239` (same on both sides, verified)

## Architecture

### Files
| File | Purpose |
|------|---------|
| `tun_dev_raw.cpp` | Wrapper: `raw_client_*` / `raw_server_*` functions — handshake FSM, packet send/recv |
| `tun_dev_raw_client.cpp` | Client libev event loop: raw_recv_cb, tun_fd_cb, conn_timer_cb |
| `tun_dev_raw_server.cpp` | Server libev event loop |
| `tun_dev_raw.h` | Header for wrapper types/functions |
| `u2r_udp2raw.cpp` | **Single TU** compilation of all udp2raw sources via `#include` + global stubs |
| `u2r_prefix.h` | `#define` renames to avoid symbol conflicts with UDPspeeder |
| `main.cpp` | CLI: `--raw-mode 1` and `--raw-mode-key` flags; args stripped before `process_arg()` |
| `makefile` | `u2r_udp2raw.o` + `tun_dev_raw.o` compiled with `-Iudp2raw -isystem udp2raw/libev` |

### Build: Single TU approach
`u2r_udp2raw.cpp` includes at bottom (lines 141-149):
```cpp
#include "network.cpp"
#include "connection.cpp"
#include "encrypt.cpp"
#include "lib/md5.cpp"
#include "lib/pbkdf2-sha1.cpp"
#include "lib/pbkdf2-sha256.cpp"
#define polarssl_zeroize polarssl_zeroize_aes
#include "lib/aes_faster_c/aes.cpp"
#include "lib/aes_faster_c/wrapper.cpp"
#undef polarssl_zeroize
```
**THIS IS THE SUSPECTED ROOT CAUSE** — original udp2raw compiles these as separate `.o` files. Single-TU may cause static variable/function issues (e.g., `static recv_data_buf` in `reserved_parse_bare` vs `reserved_parse_safer`, both in `connection.cpp`). However, XOR+simple test shows the same behavior as AES+MD5, suggesting the encryption path works for server→client direction.

### Handshake Flow (Fake TCP)
1. Client → Server: TCP SYN (via raw socket)
2. Server → Client: TCP SYN-ACK (via raw socket) — **WORKS**
3. Client → Server: TCP ACK + BARE handshake1 `(client.my_id, 0, const_id)`
4. Server → Client: BARE handshake reply `(server.my_id, client.my_id, const_id)`
5. Client → Server: BARE handshake2 `(server.my_id, client.my_id, const_id)` — server enters `server_ready`
6. SAFER data (heartbeat 'h') — client should enter `client_ready`

### Key Bug Fixed: Server handshake1 handler
The server wrapper originally only checked `m != cn.my_id` (expecting handshake2 confirmation), but the client retransmits handshake1 with `m=0`. Now fixed to handle both cases (lines 333-360 in tun_dev_raw.cpp):
```cpp
if (m == 0) {
    // retransmit handshake reply
    send_handshake(ri, cn.my_id, o, const_id);
} else if (m == cn.my_id) {
    // handshake2 confirmation → server_ready
    cn.prepare(); cn.state.server_current_state = server_ready; ...
}
```

## Test Machines
- `rock@192.168.198.110` (Armel 32-bit): Build host & server
- `rock@192.168.198.104` (Armel 32-bit): Client
- Transfer: rsync code → .110, build on .110, `cat` binary piped to .104 (no direct .110→.104 scp auth)
- Localhost testing: run both client and server on .110

## Current Status (continued 2026-07-15)
- udp2raw is now compiled as separate object files (`u2r_network.o`,
  `u2r_connection.o`, `u2r_encrypt.o`, and crypto objects), matching upstream
  rather than being included in a single translation unit.
- The documented ARM/Linux host (`.110`) clean-builds this layout successfully.
- An earlier cross-machine run reached both `SERVER_READY` and `CLIENT_READY`.
  Its 1,278-byte encrypted heartbeat was accepted; the repeated
  `auth_verify failed` messages were subsequent kernel TCP RST frames (zero
  raw payload), not failed udp2raw encryption.
- The wrapper now drops packets marked TCP RST before invoking the encrypted
  BARE/SAFER parsers.  A final clean retest reached client handshake2 but did
  not receive the server-ready heartbeat, so full end-to-end validation remains
  open.

## Resolution (2026-07-15)

Cross-machine fake-TCP tunnelling now works end-to-end.

- Root cause for payload loss: `raw_client_send_packet()` generated a new
  udp2raw conversation ID for every FEC fragment.  The server therefore could
  not route replies back through the client's known conversation.
- Fix: retain one conversation ID for the lifetime of an integrated client
  connection, record it on the server when data arrives, and reuse it for
  server-to-client payloads.
- Verified on `.104` ↔ `.110` with `--raw-mode 1 --raw-mode-key testkey`:
  30/30 IPv4 pings succeeded in each direction over `10.22.22.0/24`, with
  roughly 20 ms RTT and zero packet loss.

## Follow-up optimization (2026-07-15)

- Raw transport security is configurable through `--raw-cipher`, `--raw-auth`,
  and `--raw-disable-anti-replay`. Legacy defaults are retained for existing
  deployments.
- Verified AES-128-CBC + HMAC-SHA1 with anti-replay enabled across `.104` ↔
  `.110`: 5/5 IPv4 pings succeeded with zero loss.
- The raw client now owns and closes its reconnect bind socket instead of
  retaining separate static sockets.
- SAFER receive vectors are now retained per raw context and cleared/reused,
  reducing heap allocations on each packet. A clean build and cross-machine
  5-packet ping passed after this change.

The `auth_verify failed` errors are from `my_decrypt` → `auth_verify` in the SAFER data path (heartbeats), NOT from BARE handshake. This means the handshake DID succeed and data flows, but SAFER packet authentication fails.

## Additional transport optimizations (2026-07-15)

- `send_data_safer()` and `send_bare()` now return the underlying raw-send
  status; oversized safer/bare payloads are rejected before stack-buffer copies.
- Client/server receive vectors reserve a small batch capacity once per context,
  avoiding repeated growth during GRO parsing.
- Raw-socket event callbacks drain up to 32 ready frames per libev wakeup,
  reducing event/syscall overhead while preserving a fairness bound for TUN I/O.
- Fixed-size key, device, and interface-name copies are explicitly terminated;
  derived key material is no longer printed during startup.
- ARM/Linux clean builds and cross-machine fake-TCP smoke tests remained green
  after these changes (5/5 IPv4 pings, 0% loss, ~20 ms RTT).

## Next Steps (suggested)

### Completed: separate udp2raw compilation
`u2r_udp2raw.cpp` now contains only shared globals/stubs.  The makefile builds
the udp2raw transport, connection, encryption, and crypto sources separately
with `-include u2r_prefix.h`.  The `.110` ARM/Linux build passed.

### Option B: Debug auth_simple verification
The remaining issue is intermittent progression from handshake2 to the first
server SAFER heartbeat.  Re-run the clean test below and capture both sides'
raw packets around handshake2 if it stalls.  Authentication itself was proven
for the successful 1,278-byte heartbeat; do not use the old RST-triggered
`auth_verify failed` noise as evidence of a key mismatch.

### Option C: Quick test commands
```bash
# Build
rsync -avz --exclude='.git' /Users/weiqiangli/tinyfecVPN/ rock@192.168.198.110:/home/rock/tinyfecVPN/
ssh rock@192.168.198.110 "cd /home/rock/tinyfecVPN && make clean && make -j4"

# Transfer to .104
ssh rock@192.168.198.110 "cat /home/rock/tinyfecVPN/tinyvpn" | ssh rock@192.168.198.104 "cat > /tmp/tv && chmod +x /tmp/tv"

# Clean kill both sides
ssh rock@192.168.198.110 "sudo killall -9 tinyvpn 2>/dev/null; for i in \$(ip link show | grep -oP 'tun\d+'); do sudo ip link del \$i 2>/dev/null; done"
ssh rock@192.168.198.104 "sudo killall -9 tv 2>/dev/null; for i in \$(ip link show | grep -oP 'tun\d+'); do sudo ip link del \$i 2>/dev/null; done"

# Start server
ssh rock@192.168.198.110 "rm -f /tmp/srv.log; nohup sudo /home/rock/tinyfecVPN/tinyvpn -s -l 0.0.0.0:9555 --raw-mode 1 --raw-mode-key testkey --sub-net 10.22.22.0 --log-level 5 > /tmp/srv.log 2>&1 &"

# Run client (note: timeout may not kill sudo child, use background + kill)
ssh rock@192.168.198.104 "sudo /tmp/tv -c -r 192.168.198.110:9555 --raw-mode 1 --raw-mode-key testkey --sub-net 10.22.22.0 --log-level 5 > /tmp/cli.log 2>&1 & sleep 10; sudo killall -9 tv 2>/dev/null"

# Check logs
ssh rock@192.168.198.104 "grep -E 'CLIENT_READY|handshake|auth_verify|CLI_HS1' /tmp/cli.log | head -20"
ssh rock@192.168.198.110 "grep -E 'SERVER_READY|received syn|changed' /tmp/srv.log | head -5"
```

### Important: Process cleanup
`timeout 10 sudo /tmp/tv ...` often leaves the `/tmp/tv` process running after timeout kills the parent shell. Always follow with `sudo killall -9 tv` on .104.
