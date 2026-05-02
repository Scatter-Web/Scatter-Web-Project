# ScatterWeb

A fully P2P, anonymous, end-to-end encrypted messaging system. No central servers. Post-quantum cryptography throughout (ML-KEM-768, ML-DSA-65). Works offline via distributed Inbox/Outbox daemons.

---

## Architecture

Five daemons communicate over local Unix sockets. The `sw` CLI connects only to the Client; it never touches the others directly.

```
sw (CLI)
  └── /run/scatterweb/client.sock
       Client  ── /run/anonrouter/daemon.sock ──  AnonRouter
                ── /run/scatterweb/inbox.sock  ──  Inbox
                └─ /run/scatterweb/outbox.sock ──  Outbox
```

**Start order:** AnonRouter → Inbox → Outbox → Client → sw

---

## Building from Source

### 1. System packages

Tested on **Ubuntu 24.04 LTS**.

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build git pkg-config \
  libssl-dev libsqlite3-dev \
  libboost-all-dev libprotobuf-dev protobuf-compiler
```

### 2. Build dependencies into `/opt/sw-deps`

All post-quantum and serialisation libraries are built from source to pin versions.

```bash
export SW_DEPS=/opt/sw-deps
sudo mkdir -p $SW_DEPS && sudo chown $USER:$USER $SW_DEPS
export PKG_CONFIG_PATH=$SW_DEPS/lib/pkgconfig:$SW_DEPS/lib64/pkgconfig
export CMAKE_PREFIX_PATH=$SW_DEPS
```

**liboqs 0.10.1** — ML-KEM-768 and ML-DSA-65:
```bash
cd /tmp
git clone --branch 0.10.1 --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja \
  -DCMAKE_INSTALL_PREFIX=$SW_DEPS -DCMAKE_BUILD_TYPE=Release \
  -DOQS_ENABLE_KEM_KYBER=ON -DOQS_ENABLE_SIG_DILITHIUM=ON \
  -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build
cmake --install liboqs/build
```

**libsodium 1.0.20** — AES-256-GCM, SHA3, Argon2id:
```bash
cd /tmp
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
tar xf libsodium-1.0.20.tar.gz
cd libsodium-1.0.20 && ./configure --prefix=$SW_DEPS
make -j$(nproc) && make install
cd /tmp
```

**libcbor 0.11.0** — CBOR serialisation:
```bash
cd /tmp
git clone --branch v0.11.0 --depth 1 https://github.com/PJK/libcbor.git
cmake -S libcbor -B libcbor/build -GNinja \
  -DCMAKE_INSTALL_PREFIX=$SW_DEPS -DCMAKE_BUILD_TYPE=Release \
  -DWITH_EXAMPLES=OFF
cmake --build libcbor/build
cmake --install libcbor/build
```

### 3. Build ScatterWeb

```bash
git clone <repo-url> scatterweb && cd scatterweb

rm -rf build   # required if the directory exists from a previous run
cmake -S . -B build -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/opt/sw-deps

cmake --build build -j$(nproc)
```

Binaries will be at:
```
build/anonrouter/sw-anonrouter
build/inbox/sw-inbox
build/outbox/sw-outbox
build/client/sw-client
build/cli/sw
```

---

## First-Time Setup

### Create runtime directories

```bash
sudo mkdir -p /run/anonrouter /run/scatterweb /var/lib/anonrouter
sudo chown $USER:$USER /run/anonrouter /run/scatterweb /var/lib/anonrouter
```

### Write config files

**`/etc/scatterweb/anonrouter.conf`**
```
listen_addr  = 0.0.0.0:9000
ipc_path     = /run/anonrouter/daemon.sock
run_dir      = /var/lib/anonrouter
node_role    = full
log_level    = info
# bootstrap  = <ip>:9000   # add a known peer to join the network
```

**`/etc/scatterweb/inbox.conf`**
```
ipc_path         = /run/scatterweb/inbox.sock
anonrouter_path  = /run/anonrouter/daemon.sock
db_path          = /var/lib/scatterweb/inbox.db
```

**`/etc/scatterweb/outbox.conf`**
```
ipc_path         = /run/scatterweb/outbox.sock
anonrouter_path  = /run/anonrouter/daemon.sock
db_path          = /var/lib/scatterweb/outbox.db
```

**`/etc/scatterweb/client.conf`**
```
keystore_path    = /var/lib/scatterweb/keystore.dat
keystore_salt    = /var/lib/scatterweb/keystore.salt
messages_db_path = /var/lib/scatterweb/messages.db
client_sock      = /run/scatterweb/client.sock
anonrouter_sock  = /run/anonrouter/daemon.sock
inbox_sock       = /run/scatterweb/inbox.sock
outbox_sock      = /run/scatterweb/outbox.sock
```

```bash
sudo mkdir -p /etc/scatterweb /var/lib/scatterweb
sudo chown $USER:$USER /etc/scatterweb /var/lib/scatterweb
```

---

## Running

Open four terminals (or use systemd/tmux). The daemons print logs to stdout.

```bash
# Terminal 1 — AnonRouter
./build/anonrouter/sw-anonrouter --config /etc/scatterweb/anonrouter.conf

# Terminal 2 — Inbox
./build/inbox/sw-inbox --config /etc/scatterweb/inbox.conf

# Terminal 3 — Outbox
./build/outbox/sw-outbox --config /etc/scatterweb/outbox.conf

# Terminal 4 — Client
./build/client/sw-client --config /etc/scatterweb/client.conf
```

Wait until the Client logs show `AnonRouter connected` before using the CLI.

### Quick start with a single script

```bash
#!/usr/bin/env bash
# Run all daemons in the background and tail their logs
set -e
BUILD=./build
CFG=/etc/scatterweb

export LD_LIBRARY_PATH=/opt/sw-deps/lib:/opt/sw-deps/lib64

$BUILD/anonrouter/sw-anonrouter --config $CFG/anonrouter.conf &> /tmp/sw-anonrouter.log &
sleep 1
$BUILD/inbox/sw-inbox    --config $CFG/inbox.conf    &> /tmp/sw-inbox.log &
$BUILD/outbox/sw-outbox  --config $CFG/outbox.conf   &> /tmp/sw-outbox.log &
sleep 1
$BUILD/client/sw-client  --config $CFG/client.conf   &> /tmp/sw-client.log &

echo "All daemons started. Logs at /tmp/sw-*.log"
echo "Stop with: pkill -f 'sw-anonrouter|sw-inbox|sw-outbox|sw-client'"
```

---

## CLI Usage (`sw`)

The `sw` binary connects to `/run/scatterweb/client.sock`. Override with `SW_SOCKET_PATH`.

### Session

```bash
sw unlock                   # prompt for passphrase; creates keystore on first run
sw lock
```

On first `unlock` the Client generates your permanent identity (Key A) and device auth certs. This takes a few seconds.

### Identity

```bash
sw id                       # show display name, fingerprint, and contact card URI
sw id set-name "Alice"
sw id qr                    # print contact card URI (share this with contacts)
```

Your **contact card URI** (`scatterweb://contact/...`) is what you share with others to initiate contact. Send it over any channel — Signal, email, in person.

### Contacts

```bash
sw contacts list
sw contacts add "scatterweb://contact/<...>"   # paste their URI
sw contacts accept <contact_id>                # accept an incoming request
sw contacts decline <contact_id>
sw contacts block <contact_id>
```

### Conversations and messages

```bash
sw convs list                                  # list all conversations with unread counts
sw history <conversation_id>                   # last 20 messages
sw history <conversation_id> --limit 50

sw send <conversation_id> "hello"              # one-shot send
sw send <conversation_id> --file photo.jpg     # send a file

sw msg <conversation_id>                       # interactive mode — live updates, type to send, /quit to exit

sw react <message_id> 👍
sw delete <message_id>
```

### Groups

```bash
sw group create "Team Chat"
sw group invite <group_id> <contact_id>
sw group kick   <group_id> <contact_id>        # admin only
sw group leave  <group_id>
```

### Servers (Discord-style with channels)

```bash
sw server create "My Server"
sw server add-channel <server_id> general text
sw server add-channel <server_id> voice-1 voice
sw server set-role <server_id> <contact_id> admin
```

### Calls

```bash
sw call <conversation_id>             # audio call
sw call <conversation_id> --video     # video call
sw call accept <call_id>
sw call end    <call_id>
```

### Devices and status

```bash
sw devices list
sw devices revoke <device_id>
sw status                             # network + inbox + outbox summary
```

### Live event monitor

```bash
sw shell      # prints all push events in real time (messages, calls, contact requests…)
```

---

## Example: first conversation between two users

**User A** (shares contact card):
```bash
sw unlock
sw id qr                        # copy the scatterweb://contact/... URI
```

**User B** (sends contact request):
```bash
sw unlock
sw contacts add "scatterweb://contact/<...from A...>"
```

**User A** (accepts):
```bash
sw contacts list                # see pending_incoming from B
sw contacts accept <id>
```

**Both** can now message:
```bash
sw convs list                   # conversation appears
sw msg <conversation_id>        # interactive chat
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Cannot connect to /run/scatterweb/client.sock` | `sw-client` is not running or still starting |
| `session.unlock` returns `WRONG_PASSPHRASE` | Wrong passphrase; keystore is not modified |
| `session.unlock` returns `KEYSTORE_NOT_FOUND` | First run — a new keystore is created automatically |
| Messages stuck in `pending` | Check `sw status`; AnonRouter may not be connected or have no peers |
| Prekeys low warning | Client auto-replenishes; wait a moment then retry |
| `Error: timeout` on any command | Client is busy (DHT refresh, prekey upload); retry in a few seconds |
| `LD_LIBRARY_PATH` errors at startup | Add `/opt/sw-deps/lib` to `LD_LIBRARY_PATH` or run `ldconfig` |
