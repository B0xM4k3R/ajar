"""Parses nmap's vulners script output to find CVEs, and tags each one with what helps judge it:
which port it came from, whether the service looks like a Linux-distribution package (whose
vendor usually fixes security bugs without changing the version number, so the version-based
match may be a false alarm), and whether attackers are known to be exploiting it."""

# Names that show up in a service banner when software comes from a Linux distribution.
DISTROS = (("ubuntu", "Ubuntu"), ("debian", "Debian"), ("raspbian", "Raspberry Pi OS"),
           ("red hat", "Red Hat"), ("redhat", "Red Hat"), ("centos", "CentOS"), ("fedora", "Fedora"),
           ("suse", "SUSE"), ("almalinux", "AlmaLinux"), ("rocky", "Rocky Linux"), ("amazon linux", "Amazon Linux"))
# A found CVE the vendor may already have patched counts as this much less severe (one band).
PATCHED_DISCOUNT = 2.0


def parse_vulners(script):
    cves = []
    if script is None: return cves
    for t in script.findall(".//table"):
        el = {e.get("key"): e.text for e in t.findall("elem")}
        if el.get("type") == "cve" and el.get("id") and el.get("cvss"):
            try: cves.append({"id": el["id"], "cvss": float(el["cvss"])})
            except ValueError: pass
    return cves


def distro_of(service):
    """The Linux distribution named in an nmap <service> (as a dict of its attributes), or None."""
    text = " ".join(str((service or {}).get(k, "")) for k in ("product", "version", "extrainfo", "ostype")).lower()
    return next((name for key, name in DISTROS if key in text), None)


def merge(per_port):
    """per_port: [(port, [cves], distro_or_None)] -> one list, a CVE once even if several ports
    show it. Keeps the highest score; it only counts as 'maybe patched' if every port it came
    from is a distribution package."""
    out = {}
    for port, cves, distro in per_port:
        for c in cves:
            cur = out.get(c["id"])
            item = {"id": c["id"], "cvss": c["cvss"], "port": port, "maybe_patched": bool(distro)}
            if distro:
                item["vendor"] = distro
            if cur is None:
                out[c["id"]] = item
                continue
            patched = cur["maybe_patched"] and item["maybe_patched"]
            if item["cvss"] > cur["cvss"]:
                cur.update(cvss=item["cvss"], port=port)
            cur["maybe_patched"] = patched
            if not patched:
                cur.pop("vendor", None)
    return sorted(out.values(), key=lambda c: (-c["cvss"], c["id"]))


def effective_cvss(c):
    """The score used for the finding level: discounted when a distro may already have fixed it,
    unless attackers are known to be exploiting it, which always counts in full."""
    if c.get("kev"):
        return max(c["cvss"], 9.0)
    return c["cvss"] - (PATCHED_DISCOUNT if c.get("maybe_patched") else 0)
