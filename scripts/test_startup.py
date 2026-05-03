#!/usr/bin/env python3
"""
Mininet startup test: verify all 3 nodes are up and responsive over IPC.

Run modes:
  a) Via mininet_topology.py --run-tests (env vars set automatically)
  b) Standalone against a running Mininet session:
       MININET_H1_IP=10.0.0.1 MININET_RUN_ROOT=/tmp/sw-mininet \
           python3 scripts/test_startup.py
  c) Standalone against localhost (--local flag):
       python3 scripts/test_startup.py --local

Checks (9 total):
  - IPC socket exists for each node (3)
  - tft.status responds for each node (3)
  - channel.list returns empty for each node (3)
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

RUN_ROOT_DEFAULT = os.environ.get("MININET_RUN_ROOT", "/tmp/sw-mininet")

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


# ── IPC client (minimal, no push-event handling needed here) ─────────────────

class IPCClient:
    def __init__(self, sock_path: str, timeout: float = 10.0):
        self.sock_path  = sock_path
        self.timeout    = timeout
        self._req_id    = 0
        self._sock      = None
        self._pending:  dict[int, tuple] = {}
        self._push_events: list[dict] = []
        self._lock      = threading.Lock()
        self._send_lock = threading.Lock()

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
            "caller": "test_startup",
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

    def close(self):
        if self._sock:
            self._sock.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


# ── helpers ───────────────────────────────────────────────────────────────────

def wait_for_socket(sock_path: str, timeout: float = 15.0):
    """Poll until the Unix socket file appears (daemon may still be starting)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pathlib.Path(sock_path).exists():
            return
        time.sleep(0.2)
    raise TimeoutError(f"Socket {sock_path} did not appear within {timeout}s")


def node_dir(run_root: str, label: str) -> str:
    return os.path.join(run_root, label)


def sock_path(run_root: str, label: str) -> str:
    return os.path.join(node_dir(run_root, label), "daemon.sock")


def log_path(run_root: str, label: str) -> str:
    return os.path.join(node_dir(run_root, label), "daemon.log")


# ── main test ─────────────────────────────────────────────────────────────────

def run(run_root: str, labels: list[str]):
    print("\n── Phase 1: Socket Presence ────────────────────────────")
    for label in labels:
        sp = sock_path(run_root, label)
        check(f"{label} IPC socket appears ({sp})",
              lambda p=sp: wait_for_socket(p, timeout=15.0))

    print("\n── Phase 2: IPC Responsiveness ─────────────────────────")
    clients = {}
    for label in labels:
        sp = sock_path(run_root, label)
        if pathlib.Path(sp).exists():
            try:
                c = IPCClient(sp, timeout=8.0)
                c.connect()
                clients[label] = c
            except Exception as e:
                results.append((f"{label} IPC connect", False, str(e)))
                print(f"  [{FAIL}] {label} IPC connect: {e}")

    for label in labels:
        if label in clients:
            check(f"{label} tft.status responds",
                  lambda c=clients[label]: c.call("tft.status"))
        else:
            results.append((f"{label} tft.status responds", False, "socket not available"))
            print(f"  [{FAIL}] {label} tft.status responds: socket not available")

    print("\n── Phase 3: Clean State ────────────────────────────────")
    for label in labels:
        if label in clients:
            def _check_empty(c=clients[label], lbl=label):
                r = c.call("channel.list")
                ch = r.get("channels", [])
                assert len(ch) == 0, f"{lbl} has {len(ch)} channels at startup (expected 0)"
            check(f"{label} channel.list is empty", _check_empty)
        else:
            results.append((f"{label} channel.list is empty", False, "socket not available"))
            print(f"  [{FAIL}] {label} channel.list is empty: socket not available")

    for c in clients.values():
        c.close()

    # ── summary ───────────────────────────────────────────────────────────────
    print("\n── Results ─────────────────────────────────────────────")
    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    for name, ok, err in results:
        mark   = PASS if ok else FAIL
        suffix = f"  ← {err}" if not ok else ""
        print(f"  [{mark}] {name}{suffix}")
    print(f"\n{passed}/{total} checks passed")

    any_failed = any(not ok for _, ok, _ in results)
    if any_failed:
        for label in labels:
            lp = log_path(run_root, label)
            print(f"\n── {label} log (last 30 lines) ──")
            try:
                lines = pathlib.Path(lp).read_text().splitlines()
                for line in lines[-30:]:
                    print(f"  {line}")
            except Exception as e:
                print(f"  (could not read log: {e})")

    return passed == total


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", default=RUN_ROOT_DEFAULT,
                        help="Directory containing h1/h2/h3 subdirs with daemon.sock files")
    parser.add_argument("--local", action="store_true",
                        help="Use /tmp/sw-local instead of Mininet paths (for localhost testing)")
    parser.add_argument("--labels", default="h1,h2,h3",
                        help="Comma-separated node labels (default: h1,h2,h3)")
    args = parser.parse_args()

    run_root = args.run_root
    labels   = args.labels.split(",")

    ok = run(run_root, labels)
    sys.exit(0 if ok else 1)
