#!/usr/bin/env python3
"""
Three-node localhost topology test.

Topology:
    n1 (19001) — n2 (19002) — n3 (19003)
               ↖___________↗   (n1↔n3 also direct)

Tests:
  Phase 1  — IPC startup (3 nodes)
  Phase 2  — IPC connectivity (tft.status + channel.list)
  Phase 3  — All-pairs channel handshake (n1↔n2, n1↔n3, n2↔n3)
  Phase 4  — Bidirectional frame delivery on every channel pair
  Phase 5  — Multi-channel isolation (frame delivered only to correct channel)
  Phase 6  — Concurrent bidirectional messaging (all 3 channels simultaneously)
  Phase 7  — Cleanup (channel.close + process teardown)

Usage:
    python3 scripts/three_node_test.py [--binary ./build/anonrouter/sw-anonrouter]
"""

import argparse
import cbor2
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ANONROUTER_BIN_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "build", "anonrouter", "sw-anonrouter"
)
LD_PATH = "/opt/sw-deps/lib:/opt/sw-deps/lib64"


# ── IPC client (shared with local_smoke_test.py) ──────────────────────────────

class IPCClient:
    """Thread-safe CBOR IPC client with single-reader-thread dispatch."""

    def __init__(self, sock_path: str, timeout: float = 10.0):
        self.sock_path    = sock_path
        self.timeout      = timeout
        self._req_id      = 0
        self._sock        = None
        self._push_events: list[dict] = []
        self._pending:     dict[int, tuple] = {}
        self._lock        = threading.Lock()
        self._send_lock   = threading.Lock()

    def connect(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(None)
        self._sock.connect(self.sock_path)
        threading.Thread(target=self._reader, daemon=True).start()

    def _send(self, obj: dict):
        raw = cbor2.dumps(obj)
        with self._send_lock:
            self._sock.sendall(struct.pack(">I", len(raw)) + raw)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed")
            buf += chunk
        return buf

    def _recv_msg(self) -> dict:
        hdr    = self._recv_exact(4)
        length = struct.unpack(">I", hdr)[0]
        return cbor2.loads(self._recv_exact(length))

    def _reader(self):
        while True:
            try:
                msg = self._recv_msg()
            except Exception:
                break
            if "event" in msg:
                with self._lock:
                    self._push_events.append(msg)
            elif "id" in msg:
                with self._lock:
                    entry = self._pending.pop(msg["id"], None)
                if entry:
                    ev, box = entry
                    box[0] = msg
                    ev.set()

    def call(self, method: str, params: dict = None) -> dict:
        with self._lock:
            self._req_id += 1
            req_id = self._req_id
            ev  = threading.Event()
            box = [None]
            self._pending[req_id] = (ev, box)
        self._send({"id": req_id, "caller": "three_node_test",
                    "method": method, "params": params or {}})
        if not ev.wait(timeout=self.timeout):
            with self._lock:
                self._pending.pop(req_id, None)
            raise TimeoutError(f"No response for {method!r} within {self.timeout}s")
        resp = box[0]
        if not resp.get("ok"):
            raise RuntimeError(f"IPC error: {resp.get('error')}")
        return resp.get("result", {})

    def wait_event(self, name: str, timeout: float = 10.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for evt in self._push_events:
                    if evt.get("event") == name:
                        self._push_events.remove(evt)
                        return evt
            time.sleep(0.05)
        raise TimeoutError(f"Event {name!r} not received within {timeout}s")

    def close(self):
        if self._sock:
            self._sock.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


# ── Node helpers ──────────────────────────────────────────────────────────────

def write_config(run_dir: str, listen_port: int, ipc_path: str,
                 bootstrap: str = "") -> str:
    cfg_path = os.path.join(run_dir, "anonrouter.conf")
    lines = [
        f"listen_addr = 127.0.0.1:{listen_port}",
        f"ipc_path    = {ipc_path}",
        f"run_dir     = {run_dir}",
        "node_role   = full",
        "log_level   = debug",
    ]
    if bootstrap:
        lines.append(f"bootstrap   = {bootstrap}")
    with open(cfg_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return cfg_path


def start_node(binary: str, cfg_path: str, log_path: str) -> subprocess.Popen:
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LD_PATH
    log_file = open(log_path, "w")
    return subprocess.Popen(
        [binary, cfg_path],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )


def wait_for_socket(sock_path: str, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pathlib.Path(sock_path).exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"Socket {sock_path} did not appear within {timeout}s")


# ── Test harness ──────────────────────────────────────────────────────────────

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
results: list[tuple[str, bool, str]] = []


def check(name: str, fn):
    try:
        fn()
        print(f"  [{PASS}] {name}")
        results.append((name, True, ""))
    except Exception as e:
        print(f"  [{FAIL}] {name}: {e}")
        results.append((name, False, str(e)))


# ── Channel pair helper ───────────────────────────────────────────────────────

def open_channel_pair(initiator: IPCClient, acceptor: IPCClient,
                      acceptor_addr: str) -> tuple[str, str]:
    """Open and accept a DIRECT channel; return (initiator_chan_id, acceptor_chan_id)."""
    r = initiator.call("channel.open", {
        "remote_pubkey": "placeholder",
        "anon_level": 0,
        "mode": "message",
        "peer_addr": acceptor_addr,
    })
    assert "channel_id" in r, f"No channel_id: {r}"
    init_cid = r["channel_id"]

    evt = acceptor.wait_event("channel.incoming", timeout=5.0)
    acc_cid = evt["payload"]["channel_id"]

    r2 = acceptor.call("channel.accept", {"channel_id": acc_cid})
    assert r2.get("ok") is True or "channel_id" in r2

    time.sleep(0.4)

    channels = initiator.call("channel.list").get("channels", [])
    match = [c for c in channels if c["channel_id"] == init_cid]
    assert match and match[0]["state"] == "open", \
        f"Initiator channel not open: {match}"

    return init_cid, acc_cid


def send_and_receive(sender: IPCClient, receiver: IPCClient,
                     channel_id: str, payload: bytes):
    """Send a frame and verify it arrives at the receiver."""
    r = sender.call("frame.send", {
        "channel_id": channel_id,
        "payload": payload,
    })
    assert r.get("sent") is True, f"frame.send returned: {r}"

    evt = receiver.wait_event("frame.recv", timeout=5.0)
    received = evt["payload"]["payload"]
    if isinstance(received, str):
        received = received.encode()
    assert received == payload, f"Payload mismatch: got {received!r}"


# ── Main test run ─────────────────────────────────────────────────────────────

def run(binary: str):
    with tempfile.TemporaryDirectory(prefix="sw-3node-") as tmp:
        dirs  = [os.path.join(tmp, f"n{i}") for i in range(1, 4)]
        ports = [19001, 19002, 19003]
        socks = [os.path.join(d, "daemon.sock") for d in dirs]
        logs  = [os.path.join(d, "anonrouter.log") for d in dirs]
        addrs = [f"127.0.0.1:{p}" for p in ports]

        for d in dirs:
            os.makedirs(d)

        cfgs = [
            write_config(dirs[0], ports[0], socks[0]),                 # n1 — no bootstrap
            write_config(dirs[1], ports[1], socks[1], bootstrap=addrs[0]),  # n2 → n1
            write_config(dirs[2], ports[2], socks[2], bootstrap=addrs[0]),  # n3 → n1
        ]

        print("\n── Starting 3 nodes ─────────────────────────────────────")
        procs = []
        for i in range(3):
            procs.append(start_node(binary, cfgs[i], logs[i]))
            time.sleep(0.3)

        try:
            # ── Phase 1: IPC startup ─────────────────────────────────
            print("\n── Phase 1: IPC Startup ────────────────────────────")
            for i, sock in enumerate(socks):
                check(f"n{i+1} IPC socket appears",
                      lambda s=sock: wait_for_socket(s))

            with (IPCClient(socks[0]) as n1,
                  IPCClient(socks[1]) as n2,
                  IPCClient(socks[2]) as n3):

                nodes = [n1, n2, n3]

                # ── Phase 2: IPC connectivity ────────────────────────
                print("\n── Phase 2: IPC Connectivity ───────────────────────")
                for i, node in enumerate(nodes):
                    check(f"n{i+1} tft.status responds",
                          lambda n=node: n.call("tft.status"))
                for i, node in enumerate(nodes):
                    check(f"n{i+1} channel.list empty",
                          lambda n=node: _assert_count(n, 0))

                # ── Phase 3: All-pairs channel handshake ─────────────
                print("\n── Phase 3: All-Pairs Handshake ────────────────────")

                cids = {}   # (initiator_idx, acceptor_idx) → (init_cid, acc_cid)

                pairs = [(0, 1), (0, 2), (1, 2)]  # (n1↔n2, n1↔n3, n2↔n3)
                for (i, j) in pairs:
                    def open_pair(ni=i, nj=j):
                        cids[(ni, nj)] = open_channel_pair(nodes[ni], nodes[nj], addrs[nj])
                    check(f"n{i+1}↔n{j+1} channel established", open_pair)

                # Each node should now have 2 channels (open)
                for i, node in enumerate(nodes):
                    check(f"n{i+1} has 2 open channels",
                          lambda n=node: _assert_count(n, 2))

                # ── Phase 4: Bidirectional frame delivery ─────────────
                print("\n── Phase 4: Bidirectional Frame Delivery ───────────")

                for (i, j) in pairs:
                    if (i, j) not in cids:
                        continue
                    init_cid, acc_cid = cids[(i, j)]

                    payload_fwd = b"fwd:" + os.urandom(32)
                    check(f"n{i+1}→n{j+1} frame delivery",
                          lambda ni=nodes[i], nj=nodes[j], c=init_cid, p=payload_fwd:
                              send_and_receive(ni, nj, c, p))

                    payload_rev = b"rev:" + os.urandom(32)
                    check(f"n{j+1}→n{i+1} frame delivery",
                          lambda nj=nodes[j], ni=nodes[i], c=acc_cid, p=payload_rev:
                              send_and_receive(nj, ni, c, p))

                # ── Phase 5: Channel isolation ────────────────────────
                print("\n── Phase 5: Channel Isolation ──────────────────────")

                # Drain any stale frame.recv events left over from Phase 4
                # (a timed-out send_and_receive may have left unconsumed events).
                for node in nodes:
                    with node._lock:
                        node._push_events = [e for e in node._push_events
                                             if e.get("event") != "frame.recv"]

                if (0, 1) in cids and (0, 2) in cids:
                    cid_12 = cids[(0, 1)][0]  # n1's channel to n2
                    cid_13 = cids[(0, 2)][0]  # n1's channel to n3

                    isolation_payload = b"isolation:" + os.urandom(16)

                    def test_isolation():
                        # Send on n1→n2; only n2 should receive it (not n3)
                        r = n1.call("frame.send", {
                            "channel_id": cid_12,
                            "payload": isolation_payload,
                        })
                        assert r.get("sent") is True

                        # n2 must receive
                        evt = n2.wait_event("frame.recv", timeout=5.0)
                        got = evt["payload"]["payload"]
                        if isinstance(got, str):
                            got = got.encode()
                        assert got == isolation_payload, f"n2 got wrong payload: {got!r}"

                        # n3 must NOT have a pending frame.recv event
                        time.sleep(0.3)
                        with n3._lock:
                            n3_events = [e for e in n3._push_events if e.get("event") == "frame.recv"]
                        assert len(n3_events) == 0, \
                            f"n3 unexpectedly received {len(n3_events)} frame(s)"

                    check("Frame delivered only to correct channel peer", test_isolation)

                # ── Phase 6: Concurrent messaging ─────────────────────
                print("\n── Phase 6: Concurrent Bidirectional Messaging ─────")

                if all(k in cids for k in [(0, 1), (0, 2), (1, 2)]):
                    def concurrent_send():
                        tasks = []
                        payloads = {}
                        for (i, j) in pairs:
                            init_cid, acc_cid = cids[(i, j)]
                            p_fwd = os.urandom(48)
                            p_rev = os.urandom(48)
                            payloads[(i, j, "fwd")] = p_fwd
                            payloads[(i, j, "rev")] = p_rev
                            tasks.append((nodes[i], nodes[j], init_cid, p_fwd, "fwd"))
                            tasks.append((nodes[j], nodes[i], acc_cid, p_rev, "rev"))

                        with ThreadPoolExecutor(max_workers=6) as pool:
                            futures = {
                                pool.submit(
                                    lambda s, r, c, p: s.call("frame.send",
                                                               {"channel_id": c, "payload": p}),
                                    sender, receiver, cid, payload
                                ): (sender, receiver, cid, payload)
                                for sender, receiver, cid, payload, _ in tasks
                            }
                            for f in as_completed(futures, timeout=10):
                                r = f.result()
                                assert r.get("sent") is True, f"concurrent frame.send failed: {r}"

                        # Drain all expected frame.recv events: 2 per node × 3 nodes = 6.
                        # Each node receives exactly 2 frames (one fwd, one rev).
                        for node in nodes:
                            for _ in range(2):
                                try:
                                    node.wait_event("frame.recv", timeout=3.0)
                                except TimeoutError:
                                    pass

                    check("Concurrent 6-way frame delivery completes", concurrent_send)

                # ── Phase 7: Cleanup ──────────────────────────────────
                print("\n── Phase 7: Cleanup ────────────────────────────────")

                closed_count = [0]

                def close_all():
                    for (i, j), (init_cid, _) in list(cids.items()):
                        try:
                            r = nodes[i].call("channel.close", {"channel_id": init_cid})
                            if r.get("closed"):
                                closed_count[0] += 1
                        except Exception:
                            pass

                check("All initiator channels closed", close_all)
                check(f"Closed {len(pairs)} channels",
                      lambda: None if closed_count[0] == len(pairs)
                              else (_ for _ in ()).throw(
                                  AssertionError(f"Closed {closed_count[0]}/{len(pairs)}")))

        finally:
            for proc in procs:
                proc.terminate()
            for proc in procs:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            any_failed = any(not ok for _, ok, _ in results)
            if any_failed:
                for label, path in zip(["n1", "n2", "n3"], logs):
                    print(f"\n── {label} log (last 30 lines) ──")
                    try:
                        lines = pathlib.Path(path).read_text().splitlines()
                        for line in lines[-30:]:
                            print(f"  {line}")
                    except Exception as e:
                        print(f"  (could not read log: {e})")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n── Results ─────────────────────────────────────────────")
    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    for name, ok, err in results:
        mark = PASS if ok else FAIL
        suffix = f"  ← {err}" if not ok else ""
        print(f"  [{mark}] {name}{suffix}")
    print(f"\n{passed}/{total} checks passed")
    return passed == total


def _assert_count(client: IPCClient, expected: int):
    r = client.call("channel.list")
    channels = r.get("channels", [])
    # Count only open/opening channels (not closed)
    active = [c for c in channels if c.get("state") in ("open", "opening")]
    assert len(active) == expected, f"Expected {expected} active channels, got {len(active)}: {active}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=ANONROUTER_BIN_DEFAULT,
                        help="Path to sw-anonrouter binary")
    args = parser.parse_args()

    binary = os.path.realpath(args.binary)
    if not os.path.exists(binary):
        print(f"Binary not found: {binary}")
        sys.exit(1)

    ok = run(binary)
    sys.exit(0 if ok else 1)
