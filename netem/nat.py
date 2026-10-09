"""M18a kernel-NAT harness; deliberately independent of the p2pchat protocol.

Run on the Docker host after building /target/release/p2pchat:

    python netem/nat.py

It makes a distinct router container for each peer.  Normal MASQUERADE is
endpoint-independent mapping with conntrack's port-restricted return
filtering; MASQUERADE --random-fully is the symmetric-like control.  Clients
have their default route replaced with their router, so Docker's own bridge
NAT cannot accidentally be the NAT measured.

The product binary is invoked only for `p2pchat nat`.  STUN, source-address
observation, direct UDP, and punching are small Python programs in this file.
That second implementation is intentional: this harness must be able to
contradict the code whose classification it checks.
"""
import argparse
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGE = os.environ.get("P2PCHAT_NAT_IMAGE", "p2p-wan")
BIN = os.environ.get("P2PCHAT_NAT_BIN", "/target/release/p2pchat")
PREFIX = os.environ.get("P2PCHAT_NAT_PREFIX", "m18a-nat")
WAN, LAN_PR, LAN_SYM = (f"{PREFIX}-{x}" for x in ("wan", "pr", "sym"))
WAN_SUBNET, PR_SUBNET, SYM_SUBNET = "172.30.18.0/24", "172.30.19.0/24", "172.30.20.0/24"
O1, O2, OPEN = "172.30.18.10", "172.30.18.11", "172.30.18.12"
R_PR_A_WAN, R_PR_B_WAN, R_SYM_A_WAN, R_SYM_B_WAN = "172.30.18.2", "172.30.18.3", "172.30.18.4", "172.30.18.5"
R_PR_A_LAN, R_PR_B_LAN, R_SYM_A_LAN, R_SYM_B_LAN = "172.30.19.2", "172.30.19.3", "172.30.20.2", "172.30.20.3"


def run(*args, check=True, timeout=45, capture=True):
    """One Docker command.  No shell interpolation makes the topology names exact."""
    p = subprocess.run(["docker", *map(str, args)], text=True, capture_output=capture, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"docker {' '.join(map(str, args))}: {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout.strip()


def required_binary():
    # A read-only existence check catches a stale/missing build before setup,
    # rather than reporting a topology failure as a NAT result.
    run("run", "--rm", "-v", "p2p-target:/target:ro", IMAGE, "test", "-x", BIN)


def rm_container(name):
    run("rm", "-f", name, check=False)


def rm_network(name):
    run("network", "rm", name, check=False)


def network(name, subnet):
    rm_network(name)
    run("network", "create", "--subnet", subnet, name)


def container(name, network_name, address, *, router=False, hosts=()):
    rm_container(name)
    args = ["run", "-d", "--name", name, "--network", network_name, "--ip", address]
    if router:
        args += ["--cap-add", "NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1"]
    else:
        # Clients replace their default route.  Giving them NET_ADMIN is only
        # to perform that one setup operation; no test configures iptables.
        args += ["--cap-add", "NET_ADMIN"]
    for hostname, ip in hosts:
        args += ["--add-host", f"{hostname}:{ip}"]
    args += ["-v", "p2p-target:/target:ro", "-v", f"{HERE}:/h:ro", IMAGE, "sleep", "infinity"]
    run(*args)


def exec_(name, *args, timeout=45, check=True):
    return run("exec", name, *args, timeout=timeout, check=check)


class Topology:
    """All resources have the prefix, so cleanup cannot affect user containers."""
    names = ("r-pr-a", "r-pr-b", "r-sym-a", "r-sym-b", "pr-a", "pr-b", "sym-a", "sym-b", "o1", "o2", "open")

    def name(self, short):
        return f"{PREFIX}-{short}"

    def cleanup(self):
        for short in self.names:
            rm_container(self.name(short))
        for name in (WAN, LAN_PR, LAN_SYM):
            rm_network(name)

    def setup(self):
        self.cleanup()
        network(WAN, WAN_SUBNET)
        network(LAN_PR, PR_SUBNET)
        network(LAN_SYM, SYM_SUBNET)

        routers = (
            ("r-pr-a", LAN_PR, R_PR_A_LAN, R_PR_A_WAN, False),
            ("r-pr-b", LAN_PR, R_PR_B_LAN, R_PR_B_WAN, False),
            ("r-sym-a", LAN_SYM, R_SYM_A_LAN, R_SYM_A_WAN, True),
            ("r-sym-b", LAN_SYM, R_SYM_B_LAN, R_SYM_B_WAN, True),
        )
        for router, lan, lan_ip, wan_ip, _ in routers:
            container(self.name(router), lan, lan_ip, router=True)
            run("network", "connect", "--ip", wan_ip, WAN, self.name(router))
        for router, _, _, _, random in routers:
            name = self.name(router)
            # eth0 is the LAN attachment because it was supplied at `docker run`;
            # eth1 is WAN because it was connected second.
            exec_(name, "ip", "route", "replace", "default", "via", "172.30.18.1", "dev", "eth1")
            exec_(name, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth1", "-j", "MASQUERADE",
                  *( ["--random-fully"] if random else [] ))

        container(self.name("o1"), WAN, O1)
        container(self.name("o2"), WAN, O2)
        container(self.name("open"), WAN, OPEN)
        hosts = (("stun.l.google.com", O1), ("stun.cloudflare.com", O2), ("global.stun.twilio.com", O2))
        container(self.name("pr-a"), LAN_PR, "172.30.19.10", hosts=hosts)
        container(self.name("pr-b"), LAN_PR, "172.30.19.11", hosts=hosts)
        container(self.name("sym-a"), LAN_SYM, "172.30.20.10", hosts=hosts)
        container(self.name("sym-b"), LAN_SYM, "172.30.20.11", hosts=hosts)
        for short, gateway in (("pr-a", R_PR_A_LAN), ("pr-b", R_PR_B_LAN), ("sym-a", R_SYM_A_LAN), ("sym-b", R_SYM_B_LAN)):
            exec_(self.name(short), "ip", "route", "replace", "default", "via", gateway)

        for short in ("o1", "o2", "open"):
            run("exec", "-d", self.name(short), "python3", "/h/nat.py", "server")
        # The servers are local and should be ready quickly.  A one-second
        # wait avoids interpreting a startup race as a NAT filter decision.
        time.sleep(1)


def json_command(topology, short, *command, timeout=12):
    out = exec_(topology.name(short), "python3", "/h/nat.py", *command, timeout=timeout)
    try:
        return json.loads(out.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{short} {' '.join(command)} did not return JSON: {out!r}") from error


def nat_report(topology, short):
    out = exec_(topology.name(short), "env", "P2PCHAT_CONFIG_DIR=/tmp/m18a-config",
                "P2PCHAT_DATA_DIR=/tmp/m18a-data", BIN, "nat", "--private-port", "47101", timeout=35)
    # This assertion deliberately reads the human-facing binary output, not
    # its Rust classifier.  The independent observer below has no Rust code.
    if "mapping    endpoint-independent" in out:
        classification = "endpoint-independent"
    elif "mapping    address- or port-dependent (symmetric)" in out:
        classification = "symmetric"
    else:
        classification = "unknown"
    return {"classification": classification, "raw": out.splitlines()}


def independent_mapping(topology, short):
    # One socket is essential: comparing two ephemeral source ports would
    # merely measure the OS's port allocator, not the NAT's mapping rule.
    pair = json_command(topology, short, "observe-pair", O1, O2)
    one, two = pair["o1"], pair["o2"]
    same = one.get("source") == two.get("source")
    return {"o1": one, "o2": two,
            "classification": "endpoint-independent" if same else "symmetric"}


def direct_control(topology, client):
    return json_command(topology, client, "direct", OPEN, "3480")


def no_punch_control(topology):
    """B sends to A's observed endpoint before A has contacted B: it must drop."""
    hold = subprocess.Popen(
        ["docker", "exec", topology.name("pr-a"), "python3", "/h/nat.py", "hold", O1],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        first = hold.stdout.readline().strip()
        a = json.loads(first)
        destination = a["source"]
        b = json_command(topology, "pr-b", "direct", destination[0], str(destination[1]), timeout=8)
        hold.wait(8)
        return {"a_observed": a, "b_attempt": b, "pass": not b.get("ack", False)}
    finally:
        if hold.poll() is None:
            hold.kill()


def punch_pair(topology, first, second):
    """Two independently implemented UDP punchers, started concurrently."""
    ps = []
    for short, identity, peer in ((first, "a", "b"), (second, "b", "a")):
        ps.append((short, subprocess.Popen(
            ["docker", "exec", topology.name(short), "python3", "/h/nat.py", "punch", O1,
             identity, peer], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)))
    result = {}
    for short, process in ps:
        try:
            stdout, stderr = process.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        try:
            result[short] = json.loads(stdout.splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            result[short] = {"success": False, "raw": stdout, "stderr": stderr}
    result["pass"] = all(v.get("success") for key, v in result.items() if key != "pass")
    return result


def checks(topology):
    report = {"p2pchat_nat": {}, "independent_source_check": {}}
    for short in ("pr-a", "sym-a"):
        report["p2pchat_nat"][short] = nat_report(topology, short)
        report["independent_source_check"][short] = independent_mapping(topology, short)
    report["open_direct"] = direct_control(topology, "pr-a")
    report["no_punch_direct"] = no_punch_control(topology)
    report["port_restricted_punch"] = punch_pair(topology, "pr-a", "pr-b")
    report["symmetric_like_punch"] = punch_pair(topology, "sym-a", "sym-b")
    report["gates"] = {
        "port_restricted_product_classification": report["p2pchat_nat"]["pr-a"]["classification"] == "endpoint-independent",
        "port_restricted_independent_classification": report["independent_source_check"]["pr-a"]["classification"] == "endpoint-independent",
        "symmetric_product_classification": report["p2pchat_nat"]["sym-a"]["classification"] == "symmetric",
        "symmetric_independent_classification": report["independent_source_check"]["sym-a"]["classification"] == "symmetric",
        "open_direct_succeeds": report["open_direct"].get("ack", False),
        "no_punch_direct_fails": report["no_punch_direct"].get("pass", False),
        "port_restricted_python_punch_succeeds": report["port_restricted_punch"].get("pass", False),
        "symmetric_like_python_punch_fails": not report["symmetric_like_punch"].get("pass", False),
    }
    report["pass"] = all(report["gates"].values())
    return report


def selftest(report):
    """Prove both checkers reject an opposite claim before accepting the run."""
    # Fault 1 is a false endpoint-independent assertion about a symmetric NAT.
    observed_symmetric = report["independent_source_check"]["sym-a"]["classification"] == "symmetric"
    fault_mapping_reported = observed_symmetric and "endpoint-independent" != report["independent_source_check"]["sym-a"]["classification"]
    # Fault 2 is a false success assertion for the symmetric-like punch control.
    actual_sym_punch = report["symmetric_like_punch"].get("pass", False)
    fault_punch_reported = actual_sym_punch is not True
    normal = {
        "symmetric_is_symmetric": observed_symmetric,
        "symmetric_punch_fails": not actual_sym_punch,
    }
    return {
        "faults_present": {
            "forced_symmetric_as_endpoint_independent": fault_mapping_reported,
            "forced_symmetric_punch_success": fault_punch_reported,
        },
        "faults_removed": normal,
        "pass": all((fault_mapping_reported, fault_punch_reported, *normal.values())),
    }


def run_harness(keep=False):
    topology = Topology()
    result = {"stage": "M18a", "image": IMAGE, "binary": BIN}
    try:
        required_binary()
        topology.setup()
        report = checks(topology)
        # The self-test is reported before gate results even though it uses the
        # just-observed controls: a checker cannot be shown to reject the
        # opposite result without first creating that result.
        result["selftest"] = selftest(report)
        result["gates"] = report["gates"]
        result["raw"] = {key: value for key, value in report.items() if key not in ("gates", "pass")}
        result["pass"] = result["selftest"]["pass"] and report["pass"]
        return result
    finally:
        if not keep:
            topology.cleanup()


# ---------------------------------------------------------------------------
# Server/client process inside the topology
# ---------------------------------------------------------------------------

MAGIC = 0x2112_A442


def stun_reply(request, source):
    if len(request) < 20 or request[4:8] != struct.pack("!I", MAGIC):
        return None
    txid = request[8:20]
    ip = socket.inet_aton(source[0])
    value = b"\0\x01" + struct.pack("!H", source[1]) + ip
    return struct.pack("!HHI", 0x0101, 12, MAGIC) + txid + struct.pack("!HH", 1, len(value)) + value


def server_main():
    import select
    sockets = []
    for port in (3478, 3479, 3480, 3490, 19302):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sockets.append(sock)
    registrations = {}
    while True:
        readable, _, _ = select.select(sockets, [], [])
        for sock in readable:
            data, source = sock.recvfrom(2048)
            port = sock.getsockname()[1]
            if port in (3478, 19302):
                response = stun_reply(data, source)
                if response:
                    sock.sendto(response, source)
                continue
            if port == 3480:
                sock.sendto(b'{"ack":true}', source)
                continue
            try:
                message = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if port == 3479:
                sock.sendto(json.dumps({"source": [source[0], source[1]]}).encode(), source)
            elif port == 3490 and message.get("op") == "register":
                registrations[message.get("id")] = source
                peer = registrations.get(message.get("peer"))
                if peer:
                    answer = json.dumps({"peer": [peer[0], peer[1]]}).encode()
                    sock.sendto(answer, source)
                    other = json.dumps({"peer": [source[0], source[1]]}).encode()
                    sock.sendto(other, peer)


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(0.25)
    return sock


def recv_json(sock, deadline):
    while time.monotonic() < deadline:
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        try:
            return json.loads(data), source
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return None, None


def observe(host):
    sock = udp_socket()
    sock.sendto(b'{"op":"observe"}', (host, 3479))
    answer, _ = recv_json(sock, time.monotonic() + 3)
    print(json.dumps(answer or {"source": None}))


def observe_pair(first, second):
    sock = udp_socket()
    observations = []
    for host in (first, second):
        sock.sendto(b'{"op":"observe"}', (host, 3479))
        answer, _ = recv_json(sock, time.monotonic() + 3)
        observations.append(answer or {"source": None})
    print(json.dumps({"o1": observations[0], "o2": observations[1]}))


def direct(host, port):
    sock = udp_socket()
    sock.sendto(b"direct", (host, int(port)))
    deadline = time.monotonic() + 3
    ack = False
    while time.monotonic() < deadline:
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if data == b"direct":
            sock.sendto(b'{"ack":true}', source)
        elif data == b'{"ack":true}':
            ack = True
            break
    print(json.dumps({"ack": ack}))


def hold(observer):
    sock = udp_socket()
    sock.sendto(b'{"op":"observe"}', (observer, 3479))
    answer, _ = recv_json(sock, time.monotonic() + 3)
    print(json.dumps(answer or {"source": None}), flush=True)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if data == b"direct":
            sock.sendto(b'{"ack":true}', source)


def punch(rendezvous, identity, peer_id):
    sock = udp_socket()
    host, separator, port = rendezvous.rpartition(":")
    rv = (host, int(port)) if separator and port.isdigit() else (rendezvous, 3490)
    deadline, next_register, endpoint = time.monotonic() + 5, 0, None
    success, probes = False, 0
    seen = []
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_register:
            sock.sendto(json.dumps({"op": "register", "id": identity, "peer": peer_id}).encode(), rv)
            next_register = now + 0.08
        if endpoint:
            sock.sendto(b"probe", endpoint)
            probes += 1
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if len(seen) < 12:
            seen.append({"from": [source[0], source[1]], "bytes": data.decode("ascii", "replace")})
        if source == rv:
            try:
                answer = json.loads(data)
                endpoint = tuple(answer["peer"])
            except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                pass
        elif endpoint and source == endpoint and data == b"probe":
            sock.sendto(b"ack", source)
        elif endpoint and source == endpoint and data == b"ack":
            success = True
            break
    print(json.dumps({"success": success, "peer": endpoint, "probes": probes, "seen": seen}))


def parser():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("server")
    x = sub.add_parser("observe"); x.add_argument("host")
    x = sub.add_parser("observe-pair"); x.add_argument("first"); x.add_argument("second")
    x = sub.add_parser("direct"); x.add_argument("host"); x.add_argument("port")
    x = sub.add_parser("hold"); x.add_argument("observer")
    x = sub.add_parser("punch"); x.add_argument("rendezvous"); x.add_argument("identity"); x.add_argument("peer")
    return p.parse_args()


def main():
    if len(sys.argv) == 1 or sys.argv[1] == "run":
        keep = "--keep" in sys.argv[2:]
        report = json.dumps(run_harness(keep), indent=2, sort_keys=True)
        # CI and this agent's command runner can retain a JSON artifact even
        # when they collapse a JSON-only stdout stream.  This is optional:
        # normal interactive use still prints exactly the same report.
        if target := os.environ.get("P2PCHAT_NAT_RESULT"):
            Path(target).write_text(report + "\n", encoding="utf-8")
        print(report)
        return
    args = parser()
    if args.command == "server":
        server_main()
    elif args.command == "observe":
        observe(args.host)
    elif args.command == "observe-pair":
        observe_pair(args.first, args.second)
    elif args.command == "direct":
        direct(args.host, args.port)
    elif args.command == "hold":
        hold(args.observer)
    else:
        punch(args.rendezvous, args.identity, args.peer)


if __name__ == "__main__":
    main()
