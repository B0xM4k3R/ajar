"""Parses nmap's vulners script output to find critical CVEs."""
def parse_vulners(script):
    cves = []
    if script is None: return cves
    for t in script.findall(".//table"):
        el = {e.get("key"): e.text for e in t.findall("elem")}
        if el.get("type") == "cve" and el.get("id") and el.get("cvss"):
            try: cves.append({"id": el["id"], "cvss": float(el["cvss"])})
            except ValueError: pass
    return cves
