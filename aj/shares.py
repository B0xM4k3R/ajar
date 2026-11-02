"""What's actually inside an open share.

When a file share allows guest access, anyone on the network can already read it, so
Ajar lists what's being served and flags the sensitive stuff: documents, photos, and
especially anything that looks like passwords or financial records. It only lists names
and sizes. It never downloads a file or tries a password. The dashboard gives you an
smb:// or ftp:// link your own file manager opens, so you can look for yourself.

Listing is read-only and limited (top level, capped count) so a scan stays quick.
"""
import ftplib
import re
import socket

# filename -> category, most sensitive first. The first match wins.
CATEGORY_RULES = [
    ("credentials", re.compile(
        r"(password|passwd|\bpwd\b|secret|credential|\.env$|id_rsa|\.pem$|\.ppk$|\.kdbx$|"
        r"\.key$|keystore|wallet\.dat|\.ovpn$|\.sql$|\.htpasswd)", re.I)),
    ("financial", re.compile(
        r"(tax|invoice|\bw-?2\b|\b1099\b|payroll|paystub|bank|statement|budget|quickbooks|\.qb[wo]$|accounts?)", re.I)),
    ("backups", re.compile(r"(backup|\bbak\b|\.bak$|\.tar$|\.tgz$|\.zip$|\.7z$|\.img$|\.vhdx?$|timemachine|\.dmg$)", re.I)),
    ("documents", re.compile(r"\.(docx?|pdf|xlsx?|pptx?|csv|txt|rtf|odt|ods|pages|numbers)$", re.I)),
    ("photos", re.compile(r"\.(jpe?g|png|heic|gif|tiff?|raw|cr[23]|nef|arw|dng|mp4|mov|avi|mkv)$", re.I)),
]
CATEGORY_LABEL = {"credentials": "what looks like passwords or keys", "financial": "financial records",
                  "backups": "backups", "documents": "documents", "photos": "photos and videos"}
SENSITIVE = {"credentials", "financial"}
MAX_FILES = 200


def category_of(name):
    for cat, rx in CATEGORY_RULES:
        if rx.search(name):
            return cat
    return None


def classify(entries):
    """From a list of entries (dicts with 'name', optional 'is_dir'), work out which
    categories are exposed and pick a couple of telling examples of the sensitive ones."""
    cats, examples = {}, []
    for e in entries:
        if e.get("is_dir"):
            continue
        cat = category_of(e["name"])
        if cat:
            cats.setdefault(cat, 0)
            cats[cat] += 1
            if cat in SENSITIVE and len(examples) < 3 and e["name"] not in examples:
                examples.append(e["name"])
    order = [c for c, _ in CATEGORY_RULES]
    categories = sorted(cats, key=order.index)
    return {"categories": categories, "sensitive": bool(set(categories) & SENSITIVE),
            "examples": examples, "counts": cats}


def describe(info):
    """A short human phrase of what a share holds, for a finding or the timeline."""
    if not info or not info["categories"]:
        return ""
    parts = [CATEGORY_LABEL[c] for c in info["categories"]]
    phrase = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    if info["examples"]:
        phrase += f" ({', '.join(info['examples'][:2])})"
    return phrase


# ---------------------------------------------------------------- SMB (via nmap smb-ls)

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_smb_ls(script):
    """Reads nmap's smb-ls structured output into {share name: [entries]}.
    ls.lua nests volumes -> (volume, files) -> (size, time, filename); a directory's
    size is the literal '<DIR>'."""
    out = {}
    vols = next((t for t in script.findall("table") if t.get("key") == "volumes"), None)
    if vols is None:
        return out
    for vol in vols.findall("table"):
        name = None
        files_tbl = None
        for child in vol:
            if _local(child.tag) == "elem" and child.get("key") == "volume":
                name = (child.text or "").strip()
            elif _local(child.tag) == "table" and child.get("key") == "files":
                files_tbl = child
        if not name:
            continue
        share = name.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1] or name
        entries = []
        for row in (files_tbl.findall("table") if files_tbl is not None else []):
            rec = {e.get("key"): (e.text or "") for e in row if _local(e.tag) == "elem"}
            fn = (rec.get("filename") or "").strip()
            if not fn or fn in (".", ".."):
                continue
            size = (rec.get("size") or "").strip()
            entries.append({"name": fn, "is_dir": size.upper() == "<DIR>",
                            "size": None if size.upper() == "<DIR>" or not size.isdigit() else int(size)})
            if len(entries) >= MAX_FILES:
                break
        out[share] = entries
    return out


# ---------------------------------------------------------------- anonymous FTP (stdlib)

FTP_UNIX = re.compile(r"^([\-dl])[rwxsStT\-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+(.+)$")
FTP_WIN = re.compile(r"^\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}(?:[AP]M)?\s+(<DIR>|\d+)\s+(.+)$", re.I)


def parse_ftp_list(lines):
    """Parses the raw lines of an FTP LIST, in either the common Unix or Windows/IIS
    format. Unknown lines are returned as plain names."""
    entries = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        m = FTP_UNIX.match(line)
        if m:
            kind, size, name = m.groups()
            entries.append({"name": name.strip(), "is_dir": kind == "d",
                            "size": None if kind != "-" else int(size)})
            continue
        m = FTP_WIN.match(line)
        if m:
            size, name = m.groups()
            entries.append({"name": name.strip(), "is_dir": size.upper() == "<DIR>",
                            "size": None if size.upper() == "<DIR>" else int(size)})
            continue
        name = line.split()[-1] if line.split() else line
        if name not in (".", ".."):
            entries.append({"name": name, "is_dir": False, "size": None})
    return [e for e in entries if e["name"] not in (".", "..")][:MAX_FILES]


def list_ftp(ip, timeout=6):
    """Lists the root of an anonymous FTP server, read-only. Returns [] on any trouble,
    because a server that won't list is simply one we report nothing about."""
    ftp = ftplib.FTP()
    try:
        ftp.connect(ip, 21, timeout=timeout)
        ftp.login()  # anonymous
        lines = []
        try:
            ftp.retrlines("LIST", lines.append)
        except ftplib.all_errors:
            names = ftp.nlst()  # fall back to bare names
            return [{"name": n.rsplit("/", 1)[-1], "is_dir": False, "size": None}
                    for n in names if n.rsplit("/", 1)[-1] not in (".", "..")][:MAX_FILES]
        return parse_ftp_list(lines)
    except (ftplib.all_errors, OSError, socket.timeout):
        return []
    finally:
        try:
            ftp.quit()
        except (ftplib.all_errors, OSError):
            try:
                ftp.close()
            except OSError:
                pass
