"""End-of-life software: things that no longer get security fixes, so every flaw found in them
stays open for good. Matched against what Ajar already learns about a device: the operating system
guess, service versions, and web and SSH banners.

Only well-documented end-of-support dates are listed, and a rule only fires once its date has
passed. This is deliberately a short, careful list, not a complete one: a device not flagged here
may still be out of date. Matching is on text, so findings say "looks like"."""
import re
import time

# (name, regex on lower-case text, end-of-support date, regex that cancels the match)
RULES = [
    ("Windows XP", r"windows xp", "2014-04-08", None),
    ("Windows Vista", r"windows vista", "2017-04-11", None),
    ("Windows 7", r"windows 7(?![0-9])", "2020-01-14", r"windows 1[01]"),
    ("Windows 8", r"windows 8(?![0-9.])", "2016-01-12", r"windows 1[01]"),
    ("Windows 8.1", r"windows 8\.1", "2023-01-10", r"windows 1[01]"),
    ("Windows Server 2003", r"server 2003", "2015-07-14", None),
    ("Windows Server 2008", r"server 2008", "2020-01-14", r"server 20(12|16|19|22|25)"),
    ("Windows Server 2012", r"server 2012", "2023-10-10", r"server 20(16|19|22|25)"),
    ("Linux 2.6", r"linux 2\.6", "2016-03-01", None),
    ("Apache 2.0", r"apache(?: httpd)?[/ ]2\.0\.\d", "2013-07-10", None),
    ("Apache 2.2", r"apache(?: httpd)?[/ ]2\.2\.\d", "2017-12-31", None),
    ("Apache Tomcat 7", r"tomcat[/ ]7\.\d", "2021-03-31", None),
    ("PHP 5", r"php/5\.\d", "2018-12-31", None),
    ("PHP 7", r"php/7\.[0-4](?!\d)", "2022-11-28", None),
    ("PHP 8.0", r"php/8\.0(?!\d)", "2023-11-26", None),
    ("OpenSSL 0.9", r"openssl[/ ]0\.9\.\d", "2015-12-31", None),
    ("OpenSSL 1.0", r"openssl[/ ]1\.0\.\d", "2019-12-31", None),
    ("OpenSSL 1.1", r"openssl[/ ]1\.1\.[01]", "2023-09-11", None),
    ("Microsoft IIS 6", r"microsoft-iis/6\.0", "2015-07-14", None),
    ("Microsoft IIS 7", r"microsoft-iis/7\.[05]", "2020-01-14", None),
    ("Microsoft IIS 8", r"microsoft-iis/8\.[05]", "2023-10-10", None),
    ("Python 2", r"python/2\.\d", "2020-01-01", None),
]


def find(texts, now=None):
    """The end-of-life software that `texts` (banners, OS guesses...) mention: [{name, ended}]."""
    today = time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))
    text = " | ".join(str(t).lower() for t in texts if t)
    out, seen = [], set()
    for name, rx, ended, cancel in RULES:
        if ended > today or name in seen:
            continue
        if re.search(rx, text) and not (cancel and re.search(cancel, text)):
            out.append({"name": name, "ended": ended})
            seen.add(name)
    return out


def month_year(iso_date):
    return time.strftime("%B %Y", time.strptime(iso_date, "%Y-%m-%d"))


def describe(hits):
    return ", ".join(f"{h['name']} (support ended {month_year(h['ended'])})" for h in hits[:4]) + (" and more" if len(hits) > 4 else "")


# nmap often says "Linux 2.6.x" for much newer kernels (its fingerprints are grouped coarsely), so that
# guess is never taken as evidence. Only the computer itself reporting it counts.
FUZZY_OS_GUESSES = {"Linux 2.6"}


def os_hits(audit, now=None):
    """(end-of-life operating systems named by the OS guess, whether that OS is certain). The OS is
    certain only for the computer running Ajar, which reports its own. A guess by nmap is not."""
    o = (audit or {}).get("os") or {}
    certain = o.get("source") == "this computer"
    hits = find([o.get("name", "")], now)
    return ([h for h in hits if certain or h["name"] not in FUZZY_OS_GUESSES], certain)


def texts_for(audit):
    """Everything in a device's audit that names software (banners and service versions), ready
    for find(). The operating-system guess is handled separately, by os_hits()."""
    a = audit or {}
    out = []
    out += [str(v) for v in (a.get("versions") or {}).values()]
    for p in (a.get("probes") or {}).values():
        h, s = p.get("http") or {}, p.get("ssh") or {}
        out += [h.get("server", ""), h.get("powered_by", ""), s.get("software", ""), s.get("banner", ""), p.get("banner", "")]
    return [t for t in out if t]
