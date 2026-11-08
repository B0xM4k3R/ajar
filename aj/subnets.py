"""Validates lists of networks the person types in (for the isolation check and extra subnets).
Only private IPv4 ranges of up to 256 addresses, so a typo can't turn into a scan of the internet
or of a huge range."""
import ipaddress

# The three private IPv4 ranges (RFC 1918). Checked directly rather than through ipaddress's is_private,
# whose answer for edge ranges (0.0.0.0/x, 100.64/10, 192.0.0.x) differs between Python versions.
PRIVATE_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def clean(raw, own_subnet=None, limit=4, min_prefix=24):
    """Returns (kept, rejected). kept: normalized CIDR strings. rejected: [(text, reason)]."""
    kept, rejected = [], []
    own = None
    try:
        own = ipaddress.ip_network(own_subnet, strict=False) if own_subnet else None
    except ValueError:
        pass
    items = raw if isinstance(raw, (list, tuple)) else str(raw or "").replace(",", " ").split()
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            rejected.append((text[:40], "not a network address like 192.168.1.0/24"))
            continue
        if net.version != 4:
            reason = "only IPv4 networks are supported"
        elif not any(net.subnet_of(p) for p in PRIVATE_RANGES):
            reason = "only private home or office ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)"
        elif net.prefixlen < min_prefix:
            reason = f"too large: use /{min_prefix} or smaller (at most {2 ** (32 - min_prefix)} addresses)"
        elif own and net.overlaps(own):
            reason = "that's the network Ajar is on already"
        elif any(net.overlaps(ipaddress.ip_network(k)) for k in kept):
            reason = "overlaps another one in the list"
        elif len(kept) >= limit:
            reason = f"at most {limit} networks"
        else:
            kept.append(str(net))
            continue
        rejected.append((text[:40], reason))
    return kept, rejected
