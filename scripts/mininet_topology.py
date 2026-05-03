#!/usr/bin/env python3
"""
Mininet topology for ScatterWeb AnonRouter network simulation.

Topology: 3 hosts (h1, h2, h3) connected via a central switch s1.
Links have configurable latency and loss to simulate WAN conditions.

Requirements:
    sudo apt install mininet python3-mininet
    Must be run as root (or via sudo).

Usage:
    sudo python3 scripts/mininet_topology.py [--latency 50] [--loss 1]
    # Leaves the network running; use Ctrl-C to tear down.

    # Or use as a context for running tests:
    sudo python3 scripts/mininet_topology.py --run-tests
"""

import argparse
import os
import sys
import time

try:
    from mininet.net import Mininet
    from mininet.topo import Topo
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    from mininet.cli import CLI
except ImportError:
    print("ERROR: Mininet not installed. Run: sudo apt install mininet python3-mininet")
    sys.exit(1)

ANONROUTER_BIN = os.path.join(
    os.path.dirname(__file__), "..", "build", "anonrouter", "sw-anonrouter"
)
LD_PATH = "/opt/sw-deps/lib:/opt/sw-deps/lib64"


class ScatterWebTopo(Topo):
    """3-host star topology with configurable link parameters."""

    def build(self, latency_ms=50, loss_pct=1):
        s1 = self.addSwitch("s1")
        for i in range(1, 4):
            h = self.addHost(f"h{i}")
            self.addLink(h, s1,
                         cls=TCLink,
                         delay=f"{latency_ms}ms",
                         loss=loss_pct)


def write_config(run_dir: str, listen_ip: str, listen_port: int,
                 ipc_path: str, bootstrap: str = "") -> str:
    os.makedirs(run_dir, exist_ok=True)
    cfg_path = os.path.join(run_dir, "anonrouter.conf")
    lines = [
        f"listen_addr = {listen_ip}:{listen_port}",
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


def run_topology(latency_ms: int, loss_pct: float, run_tests: bool):
    setLogLevel("info")
    topo = ScatterWebTopo(latency_ms=latency_ms, loss_pct=loss_pct)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    h1, h2, h3 = net.get("h1"), net.get("h2"), net.get("h3")
    h1_ip = h1.IP()
    port  = 19001
    run_root = "/tmp/sw-mininet"

    cfgs = [
        write_config(f"{run_root}/h1", h1_ip, port, f"{run_root}/h1/daemon.sock"),
        write_config(f"{run_root}/h2", h2.IP(), port, f"{run_root}/h2/daemon.sock",
                     bootstrap=f"{h1_ip}:{port}"),
        write_config(f"{run_root}/h3", h3.IP(), port, f"{run_root}/h3/daemon.sock",
                     bootstrap=f"{h1_ip}:{port}"),
    ]

    env_prefix = f"LD_LIBRARY_PATH={LD_PATH}"
    procs = []
    for host, cfg, label in zip([h1, h2, h3], cfgs, ["h1", "h2", "h3"]):
        log = f"{run_root}/{label}/daemon.log"
        cmd = f"{env_prefix} {ANONROUTER_BIN} {cfg} >{log} 2>&1 &"
        host.cmd(cmd)
        print(f"[mininet] started {label} (IP={host.IP()})")

    print(f"[mininet] latency={latency_ms}ms  loss={loss_pct}%")
    print(f"[mininet] IPC sockets will appear at {run_root}/h*/daemon.sock")
    print(f"[mininet] Logs at {run_root}/h*/daemon.log")

    if run_tests:
        time.sleep(3)
        _run_tests(run_root, h1_ip)
    else:
        print("[mininet] Network running. Ctrl-C or type 'exit' to stop.")
        CLI(net)

    net.stop()


def _run_tests(run_root: str, h1_ip: str):
    """Run basic startup + messaging tests inside the Mininet environment."""
    import subprocess
    scripts_dir = os.path.dirname(__file__)
    env = os.environ.copy()
    env["MININET_H1_IP"] = h1_ip
    env["MININET_RUN_ROOT"] = run_root
    
    # Try to use venv Python if available, otherwise fall back to current executable
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        python_exe = os.path.join(venv_path, "bin", "python3")
    else:
        python_exe = sys.executable

    for script in ["test_startup.py", "test_basic_messaging.py"]:
        path = os.path.join(scripts_dir, script)
        if not os.path.exists(path):
            print(f"[mininet] {script} not found, skipping")
            continue
        print(f"\n[mininet] running {script}")
        ret = subprocess.call([python_exe, path], env=env)
        if ret != 0:
            print(f"[mininet] {script} FAILED (exit {ret})")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Mininet requires root. Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--latency", type=int, default=50,
                        help="Link latency in ms (default: 50)")
    parser.add_argument("--loss", type=float, default=1.0,
                        help="Link loss percentage (default: 1.0)")
    parser.add_argument("--run-tests", action="store_true",
                        help="Auto-run test_startup.py and test_basic_messaging.py")
    args = parser.parse_args()

    run_topology(args.latency, args.loss, args.run_tests)
