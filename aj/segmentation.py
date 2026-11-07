"""Is this network really kept apart from your other networks?

Guest and smart-home networks are only worth having if devices on them can't reach your main
network. This check is for running Ajar ON the network that should be isolated (the guest or IoT
one): you list the networks it should not be able to reach, and Ajar tries to reach them. If hosts
answer, the separation isn't working.

It only ever probes the networks you list, with an ordinary ping-style sweep, nothing more."""
import time

from .db import net_setting, set_net_setting
from .events import record
from .subnets import clean
from .tools import run_nmap

KEY = "segmentation"
TARGETS_KEY = "segmentation_targets"
MAX_TARGETS = 4


def router_like(ip):
    """Routers usually sit at .1 or .254, and answer from every network they connect."""
    return ip.rsplit(".", 1)[-1] in ("1", "254")


def evaluate(targets, reachable):
    """reachable: {cidr: [ips that answered]} -> findings."""
    findings = []
    hosts = {c: [ip for ip in ips if not router_like(ip)] for c, ips in reachable.items()}
    routers = {c: [ip for ip in ips if router_like(ip)] for c, ips in reachable.items()}
    breached = {c: ips for c, ips in hosts.items() if ips}
    if breached:
        total = sum(len(v) for v in breached.values())
        names = "; ".join(f"{len(v)} on {c}" for c, v in breached.items())
        sample = ", ".join(sorted(next(iter(breached.values())))[:3])
        findings.append({"level": "high", "id": "no_isolation", "ips": sorted(i for v in breached.values() for i in v),
                         "text": f"This network can reach {total} device{'s' if total != 1 else ''} it should be kept apart from "
                                 f"({names}, for example {sample}). If this is your guest or smart-home network, "
                                 "the separation from your main network isn't working."})
    elif any(routers.values()):
        findings.append({"level": "info", "id": "isolation_router_only",
                         "text": "Only your router answered from the other network(s). That's normal: routers answer on every "
                                 "network they connect. No other devices were reachable."})
    return findings


def run(net, own_subnet, nmap=None, now=None):
    """Probes the networks configured for this network. Returns the saved result, or None if
    none are configured. Records an event when the picture changes."""
    targets, _ = clean(net_setting(net, TARGETS_KEY, []), own_subnet, limit=MAX_TARGETS)
    if not targets:
        return None
    now = now or time.time()
    root = (nmap or run_nmap)(["-sn", "-n", "-T4", "--max-retries", "1", "--host-timeout", "8s",
                               "-PE", "-PS22,80,443,445,3389,8080", "-PA80,443"] + targets, 300)
    from ipaddress import ip_address, ip_network
    nets = [ip_network(t) for t in targets]
    reachable = {t: [] for t in targets}
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                for t, n in zip(targets, nets):
                    if ip_address(a.get("addr")) in n:
                        reachable[t].append(a.get("addr"))
    findings = evaluate(targets, reachable)
    result = {"at": now, "targets": targets, "reachable": reachable, "findings": findings}
    before = net_setting(net, KEY, None) or {}
    was = any(f["id"] == "no_isolation" for f in before.get("findings", []))
    now_bad = any(f["id"] == "no_isolation" for f in findings)
    if now_bad and not was:
        record(net, "isolation_failed", "high", findings[0]["text"], None, now)
    elif was and not now_bad:
        record(net, "problem_fixed", "info", "This network can no longer reach the networks it should be kept apart from.", None, now)
    set_net_setting(net, KEY, result)
    return result
