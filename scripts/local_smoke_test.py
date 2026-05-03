#!/usr/bin/env python3
"""
Localhost smoke test: 2 AnonRouter nodes on loopback.
Tests IPC startup, CHAN_OPEN/CHAN_ACCEPT handshake, and frame delivery.

Usage:
    python3 scripts/local_smoke_test.py [--binary ./build/anonrouter/sw-anonrouter]
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

ANONROUTER_BIN_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "build", "anonrouter", "sw-anonrouter"
)
LD_PATH = "/opt/sw-deps/lib:/opt/sw-deps/lib64"


# ── IPC client ────────────────────────────────────────────────────────────────

class IPCClient:
    """
    Thread-safe CBOR IPC client.
    A single reader thread owns the socket; responses are dispatched via
    per-request threading.Event so call() never races with push events.
    """

    def __init__(self, sock_path: str, timeout: float = 10.0):
        self.sock_path    = sock_path
        self.timeout      = timeout
        self._req_id      = 0
        self._sock        = None
        self._push_events: list[dict] = []
        self._pending:     dict[int, tuple] = {}   # req_id → (Event, box[])
        self._lock        = threading.Lock()
        self._send_lock   = threading.Lock()

    def connect(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(None)   # blocking; reader drives reads
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
        """Single reader thread — dispatches push events and request responses."""
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
            "caller": "smoke_test",
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
    proc = subprocess.Popen(
        [binary, cfg_path],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
    )
    return proc


def wait_for_socket(sock_path: str, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pathlib.Path(sock_path).exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"Socket {sock_path} did not appear within {timeout}s")


# ── Test steps ────────────────────────────────────────────────────────────────

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


def run(binary: str):
    with tempfile.TemporaryDirectory(prefix="sw-smoke-") as tmp:
        d1 = os.path.join(tmp, "n1")
        d2 = os.path.join(tmp, "n2")
        os.makedirs(d1); os.makedirs(d2)

        sock1 = os.path.join(d1, "daemon.sock")
        sock2 = os.path.join(d2, "daemon.sock")
        log1  = os.path.join(d1, "anonrouter.log")
        log2  = os.path.join(d2, "anonrouter.log")

        cfg1 = write_config(d1, 19001, sock1)
        cfg2 = write_config(d2, 19002, sock2, bootstrap="127.0.0.1:19001")

        print("\n── Starting nodes ──────────────────────────────────────")
        proc1 = start_node(binary, cfg1, log1)
        time.sleep(0.3)
        proc2 = start_node(binary, cfg2, log2)

        try:
            # ── Step 1: IPC sockets appear ───────────────────────────
            print("\n── Phase 1: IPC Startup ────────────────────────────")
            check("n1 IPC socket appears", lambda: wait_for_socket(sock1))
            check("n2 IPC socket appears", lambda: wait_for_socket(sock2))

            with IPCClient(sock1) as n1, IPCClient(sock2) as n2:

                # ── Step 2: Basic IPC response ───────────────────────
                print("\n── Phase 2: IPC Connectivity ───────────────────────")
                check("n1 tft.status responds",
                      lambda: n1.call("tft.status"))
                check("n2 tft.status responds",
                      lambda: n2.call("tft.status"))

                check("n1 channel.list returns empty",
                      lambda: _assert_empty_channels(n1))
                check("n2 channel.list returns empty",
                      lambda: _assert_empty_channels(n2))

                # ── Step 3: CHAN_OPEN / CHAN_ACCEPT handshake ─────────
                print("\n── Phase 3: Channel Handshake ──────────────────────")
                chan_id_ref = [None]

                def open_channel():
                    r = n1.call("channel.open", {
                        "remote_pubkey": "n2-placeholder",
                        "anon_level": 0,
                        "mode": "message",
                        "peer_addr": "127.0.0.1:19002",
                    })
                    assert "channel_id" in r, f"No channel_id in response: {r}"
                    chan_id_ref[0] = r["channel_id"]

                check("n1 channel.open (direct, peer_addr=n2)", open_channel)

                def n2_receives_incoming():
                    evt = n2.wait_event("channel.incoming", timeout=5.0)
                    assert evt["payload"]["anon_level"] == 0
                    return evt["payload"]["channel_id"]

                incoming_id_ref = [None]
                def check_incoming():
                    incoming_id_ref[0] = n2_receives_incoming()

                check("n2 receives channel.incoming push", check_incoming)

                def accept_channel():
                    assert incoming_id_ref[0] is not None, "No incoming channel_id"
                    r = n2.call("channel.accept", {"channel_id": incoming_id_ref[0]})
                    assert r.get("ok") is True or "channel_id" in r

                check("n2 accepts channel", accept_channel)

                # Give a moment for CHAN_ACCEPT to arrive at n1
                time.sleep(0.5)

                def n1_channel_is_open():
                    channels = n1.call("channel.list").get("channels", [])
                    assert len(channels) == 1, f"Expected 1 channel, got {len(channels)}"
                    assert channels[0]["state"] == "open", \
                        f"Channel state is {channels[0]['state']!r}, expected 'open'"

                check("n1 channel reaches open state", n1_channel_is_open)

                # ── Step 4: Frame delivery ────────────────────────────
                print("\n── Phase 4: Frame Delivery ─────────────────────────")
                test_payload = b"hello from n1 " + os.urandom(32)

                def send_frame():
                    assert chan_id_ref[0] is not None
                    r = n1.call("frame.send", {
                        "channel_id": chan_id_ref[0],
                        "payload": test_payload,
                    })
                    assert r.get("sent") is True, f"frame.send returned: {r}"

                check("n1 frame.send succeeds", send_frame)

                def frame_arrives_at_n2():
                    evt = n2.wait_event("frame.recv", timeout=5.0)
                    received = evt["payload"]["payload"]
                    assert received == test_payload, \
                        f"Payload mismatch: got {received!r}, expected {test_payload!r}"

                check("n2 receives frame with correct payload", frame_arrives_at_n2)

                # ── Step 5: Channel close ─────────────────────────────
                print("\n── Phase 5: Cleanup ────────────────────────────────")
                def close_channel():
                    assert chan_id_ref[0] is not None
                    r = n1.call("channel.close", {"channel_id": chan_id_ref[0]})
                    assert r.get("closed") is True

                check("n1 channel.close succeeds", close_channel)

        finally:
            for proc in (proc1, proc2):
                proc.terminate()
            for proc in (proc1, proc2):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            # Print log tails on failure for easier debugging
            any_failed = any(not ok for _, ok, _ in results)
            if any_failed:
                for label, path in [("n1", log1), ("n2", log2)]:
                    print(f"\n── {label} log (last 30 lines) ──")
                    try:
                        lines = pathlib.Path(path).read_text().splitlines()
                        for l in lines[-30:]:
                            print(f"  {l}")
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


def _assert_empty_channels(client: IPCClient):
    r = client.call("channel.list")
    channels = r.get("channels", [])
    assert len(channels) == 0, f"Expected 0 channels, got {len(channels)}"


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
