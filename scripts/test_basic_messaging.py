#!/usr/bin/env python3
"""
Mininet basic messaging test: frame delivery over emulated WAN conditions
(50 ms latency + 1% packet loss by default).

Run modes:
  a) Via mininet_topology.py --run-tests (env vars set automatically)
  b) Standalone against a running Mininet session:
       MININET_H1_IP=10.0.0.1 MININET_RUN_ROOT=/tmp/sw-mininet \
           python3 scripts/test_basic_messaging.py
  c) Standalone against localhost (no Mininet):
       python3 scripts/test_basic_messaging.py --local

Checks (22 total):
  Phase 1: IPC Startup            3  (sockets appear)
  Phase 2: IPC Connectivity       6  (tft.status + channel.list empty × 3)
  Phase 3: All-Pairs Handshake    7  (h1↔h2, h1↔h3, h2↔h3 open + counts)
  Phase 4: Bidirectional Frames   6  (all 6 ordered pairs deliver correctly)
  Phase 5: Cleanup                3  (close all channels + count = 3)
"""

import argparse
import cbor2
import os
import pathlib
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

RUN_ROOT_DEFAULT = os.environ.get("MININET_RUN_ROOT", "/tmp/sw-mininet")
H1_IP_DEFAULT    = os.environ.get("MININET_H1_IP",    "10.0.0.1")

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


# ── IPC client ────────────────────────────────────────────────────────────────

class IPCClient:
    def __init__(self, sock_path: str, timeout: float = 15.0):
        self.sock_path     = sock_path
        self.timeout       = timeout
        self._req_id       = 0
        self._sock         = None
        self._push_events: list[dict] = []
        self._pending:     dict[int, tuple] = {}
        self._lock         = threading.Lock()
        self._send_lock    = threading.Lock()

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

        self._send({
            "id":     req_id,
            "caller": "test_messaging",
            "method": method,
            "params": params or {},
        })

        if not ev.wait(timeout=self.timeout):
            with self._lock:
                self._pending.pop(req_id, None)
            raise TimeoutError(f"No response for {method!r} within {self.timeout}s")

        resp = box[0]
        if not resp.get("ok"):
            raise RuntimeError(f"IPC error: {resp.get('error')}")
        return resp.get("result", {})

    def wait_event(self, name: str, timeout: float = 20.0) -> dict:
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


# ── helpers ───────────────────────────────────────────────────────────────────

def wait_for_socket(sock_path: str, timeout: float = 20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pathlib.Path(sock_path).exists():
            return
        time.sleep(0.2)
    raise TimeoutError(f"Socket {sock_path} did not appear within {timeout}s")


def open_channel_pair(initiator: IPCClient, acceptor: IPCClient,
                      peer_addr: str, timeout: float = 15.0) -> tuple[bytes, bytes]:
    """
    Open a DIRECT channel from initiator to acceptor.
    Returns (initiator_chan_id, acceptor_chan_id).
    """
    r = initiator.call("channel.open", {
        "remote_pubkey": "placeholder",
        "anon_level": 0,
        "mode": "message",
        "peer_addr": peer_addr,
    })
    assert "channel_id" in r, f"channel.open missing channel_id: {r}"
    init_chan_id = r["channel_id"]

    evt = acceptor.wait_event("channel.incoming", timeout=timeout)
    acc_chan_id = evt["payload"]["channel_id"]
    assert evt["payload"]["anon_level"] == 0

    r2 = acceptor.call("channel.accept", {"channel_id": acc_chan_id})
    assert r2.get("ok") is True or "channel_id" in r2

    # Wait for CHAN_ACCEPT to propagate back — WAN adds ~100ms RTT
    time.sleep(0.5)

    return init_chan_id, acc_chan_id


def assert_channels_open(node: IPCClient, expected_count: int, label: str):
    channels = node.call("channel.list").get("channels", [])
    open_ch  = [c for c in channels if c["state"] == "open"]
    assert len(open_ch) == expected_count, \
        f"{label}: expected {expected_count} open channel(s), got {len(open_ch)} " \
        f"(states: {[c['state'] for c in channels]})"


def send_and_receive(sender: IPCClient, receiver: IPCClient,
                     chan_id: bytes, payload: bytes, label: str, timeout: float = 20.0):
    """Send a frame and assert the correct payload arrives at receiver."""
    r = sender.call("frame.send", {"channel_id": chan_id, "payload": payload})
    assert r.get("sent") is True, f"{label} frame.send returned: {r}"

    evt = receiver.wait_event("frame.recv", timeout=timeout)
    got = evt["payload"]["payload"]
    assert got == payload, f"{label} payload mismatch: got {got!r}, expected {payload!r}"


# ── main test ─────────────────────────────────────────────────────────────────

def run(run_root: str, node_addrs: dict[str, str]):
    """
    node_addrs: mapping label → "ip:port" for each AnonRouter daemon.
    Socket and log files are expected at {run_root}/{label}/daemon.{sock,log}.
    """
    labels = list(node_addrs.keys())  # e.g. ["h1", "h2", "h3"]

    def sp(label):
        return os.path.join(run_root, label, "daemon.sock")

    def lp(label):
        return os.path.join(run_root, label, "daemon.log")

    # ── Phase 1: Socket presence ──────────────────────────────────────────────
    print("\n── Phase 1: IPC Startup ─────────────────────────────────")
    for label in labels:
        check(f"{label} IPC socket appears",
              lambda p=sp(label): wait_for_socket(p, timeout=20.0))

    # ── Phase 2: IPC connectivity ─────────────────────────────────────────────
    print("\n── Phase 2: IPC Connectivity ────────────────────────────")
    nodes: dict[str, IPCClient] = {}
    for label in labels:
        path = sp(label)
        if pathlib.Path(path).exists():
            try:
                c = IPCClient(path, timeout=12.0)
                c.connect()
                nodes[label] = c
            except Exception as e:
                print(f"  [{FAIL}] {label} IPC connect: {e}")
                results.append((f"{label} IPC connect", False, str(e)))

    for label in labels:
        if label in nodes:
            check(f"{label} tft.status responds",
                  lambda c=nodes[label]: c.call("tft.status"))
        else:
            print(f"  [{FAIL}] {label} tft.status responds: socket not available")
            results.append((f"{label} tft.status responds", False, "socket not available"))

    for label in labels:
        if label in nodes:
            def _empty(c=nodes[label], lbl=label):
                r = c.call("channel.list")
                ch = r.get("channels", [])
                assert len(ch) == 0, f"{lbl}: {len(ch)} channels at startup"
            check(f"{label} channel.list empty", _empty)
        else:
            print(f"  [{FAIL}] {label} channel.list empty: socket not available")
            results.append((f"{label} channel.list empty", False, "socket not available"))

    if len(nodes) < 2:
        print("\nNot enough nodes connected — aborting further tests.")
        _summary(results, labels, run_root, lp)
        return False

    # ── Phase 3: All-pairs handshake ──────────────────────────────────────────
    print("\n── Phase 3: All-Pairs Handshake (over emulated WAN) ────")
    # We need three node labels. Gracefully skip if fewer are available.
    active = [l for l in labels if l in nodes]
    h1, h2 = nodes[active[0]], nodes[active[1]]
    h3     = nodes[active[2]] if len(active) > 2 else None

    chan_12_init = chan_12_acc = None
    chan_13_init = chan_13_acc = None
    chan_23_init = chan_23_acc = None

    def open_h1_h2():
        nonlocal chan_12_init, chan_12_acc
        chan_12_init, chan_12_acc = open_channel_pair(h1, h2, node_addrs[active[1]])

    def open_h1_h3():
        nonlocal chan_13_init, chan_13_acc
        chan_13_init, chan_13_acc = open_channel_pair(h1, h3, node_addrs[active[2]])

    def open_h2_h3():
        nonlocal chan_23_init, chan_23_acc
        chan_23_init, chan_23_acc = open_channel_pair(h2, h3, node_addrs[active[2]])

    check(f"{active[0]}↔{active[1]} channel opens", open_h1_h2)
    if h3:
        check(f"{active[0]}↔{active[2]} channel opens", open_h1_h3)
        check(f"{active[1]}↔{active[2]} channel opens", open_h2_h3)

    time.sleep(0.3)

    check(f"{active[0]} has 2 open channels",
          lambda: assert_channels_open(h1, 2 if h3 else 1, active[0]))
    check(f"{active[1]} has 2 open channels",
          lambda: assert_channels_open(h2, 2 if h3 else 1, active[1]))
    if h3:
        check(f"{active[2]} has 2 open channels",
              lambda: assert_channels_open(h3, 2, active[2]))

    # ── Phase 4: Bidirectional frame delivery ─────────────────────────────────
    print("\n── Phase 4: Bidirectional Frame Delivery (WAN with loss) ")
    # Each payload is unique so we can detect cross-channel contamination.
    payloads = {
        "h1→h2": b"msg_h1_to_h2_" + os.urandom(16),
        "h2→h1": b"msg_h2_to_h1_" + os.urandom(16),
        "h1→h3": b"msg_h1_to_h3_" + os.urandom(16),
        "h3→h1": b"msg_h3_to_h1_" + os.urandom(16),
        "h2→h3": b"msg_h2_to_h3_" + os.urandom(16),
        "h3→h2": b"msg_h3_to_h2_" + os.urandom(16),
    }

    directions = [
        ("h1→h2", h1, h2, chan_12_init),
        ("h2→h1", h2, h1, chan_12_acc),
    ]
    if h3 and chan_13_init and chan_23_init:
        directions += [
            ("h1→h3", h1, h3, chan_13_init),
            ("h3→h1", h3, h1, chan_13_acc),
            ("h2→h3", h2, h3, chan_23_init),
            ("h3→h2", h3, h2, chan_23_acc),
        ]

    for label, sender, receiver, chan_id in directions:
        if chan_id is None:
            results.append((f"{label} frame delivery", False, "channel not established"))
            print(f"  [{FAIL}] {label} frame delivery: channel not established")
            continue
        p = payloads[label]
        check(f"{label} frame delivery",
              lambda s=sender, r=receiver, c=chan_id, pay=p, lbl=label:
                  send_and_receive(s, r, c, pay, lbl, timeout=20.0))

    # ── Phase 5: Cleanup ──────────────────────────────────────────────────────
    print("\n── Phase 5: Cleanup ─────────────────────────────────────")
    close_count = [0]

    for chan_id, owner, lbl in [
        (chan_12_init, h1, f"{active[0]}↔{active[1]}"),
        (chan_13_init, h1, f"{active[0]}↔{active[2]}") if h3 else (None, None, None),
        (chan_23_init, h2, f"{active[1]}↔{active[2]}") if h3 else (None, None, None),
    ]:
        if chan_id is None or owner is None:
            continue

        def _close(c=chan_id, o=owner, l=lbl):
            r = o.call("channel.close", {"channel_id": c})
            assert r.get("closed") is True, f"{l} close returned: {r}"
            close_count[0] += 1

        check(f"{lbl} channel.close", _close)

    check("close count = 3 (or 1 if 2-node)",
          lambda: _assert_close_count(close_count[0], 3 if h3 else 1))

    for c in nodes.values():
        c.close()

    _summary(results, labels, run_root, lp)
    return all(ok for _, ok, _ in results)


def _assert_close_count(got: int, expected: int):
    assert got == expected, f"Expected {expected} close(s), got {got}"


def _summary(res, labels, run_root, log_path_fn):
    print("\n── Results ─────────────────────────────────────────────")
    passed = sum(1 for _, ok, _ in res if ok)
    total  = len(res)
    for name, ok, err in res:
        mark   = PASS if ok else FAIL
        suffix = f"  ← {err}" if not ok else ""
        print(f"  [{mark}] {name}{suffix}")
    print(f"\n{passed}/{total} checks passed")

    if any(not ok for _, ok, _ in res):
        for label in labels:
            lp = log_path_fn(label)
            print(f"\n── {label} log (last 30 lines) ──")
            try:
                lines = pathlib.Path(lp).read_text().splitlines()
                for line in lines[-30:]:
                    print(f"  {line}")
            except Exception as e:
                print(f"  (could not read log: {e})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", default=RUN_ROOT_DEFAULT,
                        help="Directory containing h1/h2/h3 subdirs (default: $MININET_RUN_ROOT)")
    parser.add_argument("--h1-ip", default=H1_IP_DEFAULT,
                        help="IP of h1 (bootstrap) as seen by h2/h3 (default: $MININET_H1_IP)")
    parser.add_argument("--port", type=int, default=19001,
                        help="UDP port all daemons listen on (default: 19001)")
    parser.add_argument("--local", action="store_true",
                        help="Use 127.0.0.1 addresses for all nodes (localhost mode)")
    args = parser.parse_args()

    port = args.port
    if args.local:
        node_addrs = {
            "h1": f"127.0.0.1:{port}",
            "h2": f"127.0.0.1:{port + 1}",
            "h3": f"127.0.0.1:{port + 2}",
        }
        run_root = args.run_root if args.run_root != RUN_ROOT_DEFAULT else "/tmp/sw-local"
    else:
        # In Mininet each host has its own IP but they all listen on the same port.
        # We only know h1's IP from the env; h2/h3 IPs are discovered via Mininet
        # host numbering (10.0.0.1, 10.0.0.2, 10.0.0.3 by default in a star topo).
        h1_ip = args.h1_ip
        parts  = h1_ip.rsplit(".", 1)
        base   = parts[0]
        last   = int(parts[1])
        node_addrs = {
            "h1": f"{base}.{last}:{port}",
            "h2": f"{base}.{last + 1}:{port}",
            "h3": f"{base}.{last + 2}:{port}",
        }
        run_root = args.run_root

    ok = run(run_root, node_addrs)
    sys.exit(0 if ok else 1)
