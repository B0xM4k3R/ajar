"""What's inside an open share: classifying files, parsing listings, findings and score."""
import unittest
import xml.etree.ElementTree as ET

import helpers  # sets up the import path and a throwaway database
from aj import audit as aj_audit
from aj import score as aj_score
from aj import shares as aj_shares

SMB_LS = """<script id="smb-ls" output="...">
<table key="volumes">
 <table>
  <elem key="volume">\\\\192.168.1.9\\Photos</elem>
  <table key="files">
   <table><elem key="size">&lt;DIR&gt;</elem><elem key="time">2024-01-01 10:00</elem><elem key="filename">Vacation</elem></table>
   <table><elem key="size">204800</elem><elem key="time">2024-02-01 09:00</elem><elem key="filename">passwords.txt</elem></table>
   <table><elem key="size">51200</elem><elem key="time">2024-03-01 09:00</elem><elem key="filename">tax_2024.pdf</elem></table>
   <table><elem key="size">8000</elem><elem key="time">2024-03-01 09:00</elem><elem key="filename">beach.jpg</elem></table>
   <table><elem key="size">0</elem><elem key="time">2024-03-01 09:00</elem><elem key="filename">.</elem></table>
  </table>
 </table>
 <table>
  <elem key="volume">\\\\192.168.1.9\\Public</elem>
  <table key="files">
   <table><elem key="size">1024</elem><elem key="time">2024-03-01 09:00</elem><elem key="filename">readme.txt</elem></table>
  </table>
 </table>
</table></script>"""

FTP_UNIX = [
    "drwxr-xr-x   2 ftp ftp    4096 Jan 01 10:00 Backups",
    "-rw-r--r--   1 ftp ftp  204800 Feb 01 09:00 bank_statement.pdf",
    "-rw-r--r--   1 ftp ftp    1234 Feb 01 09:00 notes.txt",
    "-rw-r--r--   1 ftp ftp    5000 Feb 01 09:00 .",
]
FTP_WIN = [
    "01-01-24  10:00AM       <DIR>          Photos",
    "02-01-24  09:00AM              204800 invoice_April.xlsx",
]


class Classify(unittest.TestCase):
    def test_categories_and_sensitivity(self):
        info = aj_shares.classify([
            {"name": "passwords.txt"}, {"name": "tax_2024.pdf"}, {"name": "beach.jpg"},
            {"name": "notes.docx"}, {"name": "Vacation", "is_dir": True}, {"name": "id_rsa"}])
        self.assertEqual(info["categories"], ["credentials", "financial", "documents", "photos"])
        self.assertTrue(info["sensitive"])
        self.assertIn("passwords.txt", info["examples"])
        self.assertIn("id_rsa", info["examples"])

    def test_not_sensitive_when_only_ordinary(self):
        info = aj_shares.classify([{"name": "readme.txt"}, {"name": "clip.mp4"}])
        self.assertFalse(info["sensitive"])
        self.assertEqual(info["categories"], ["documents", "photos"])

    def test_describe_reads_naturally(self):
        info = aj_shares.classify([{"name": "passwords.txt"}, {"name": "holiday.png"}])
        self.assertEqual(aj_shares.describe(info), "what looks like passwords or keys and photos and videos (passwords.txt)")
        self.assertEqual(aj_shares.describe(aj_shares.classify([])), "")


class ParseSmbLs(unittest.TestCase):
    def test_parses_volumes_files_and_dirs(self):
        out = aj_shares.parse_smb_ls(ET.fromstring(SMB_LS))
        self.assertEqual(set(out), {"Photos", "Public"})
        photos = {e["name"]: e for e in out["Photos"]}
        self.assertNotIn(".", photos)
        self.assertTrue(photos["Vacation"]["is_dir"])
        self.assertEqual(photos["passwords.txt"]["size"], 204800)
        self.assertFalse(photos["passwords.txt"]["is_dir"])
        self.assertTrue(aj_shares.classify(out["Photos"])["sensitive"])
        self.assertFalse(aj_shares.classify(out["Public"])["sensitive"])


class ParseFtp(unittest.TestCase):
    def test_unix(self):
        e = {x["name"]: x for x in aj_shares.parse_ftp_list(FTP_UNIX)}
        self.assertEqual(set(e), {"Backups", "bank_statement.pdf", "notes.txt"})  # "." dropped
        self.assertTrue(e["Backups"]["is_dir"])
        self.assertEqual(e["bank_statement.pdf"]["size"], 204800)
        self.assertTrue(aj_shares.classify(FTP_UNIX and aj_shares.parse_ftp_list(FTP_UNIX))["sensitive"])

    def test_windows(self):
        e = {x["name"]: x for x in aj_shares.parse_ftp_list(FTP_WIN)}
        self.assertTrue(e["Photos"]["is_dir"])
        self.assertEqual(e["invoice_April.xlsx"]["size"], 204800)


def share(name, access, files):
    sh = {"name": name, "access": access, "type": "", "comment": "", "files": files,
          "exposed": aj_shares.classify(files)}
    return sh


def audit_with(shares=(), ftp=None, ports=(445,)):
    a = {"ports": [{"port": p, "name": str(p)} for p in ports], "shares": list(shares), "nfs": []}
    if ftp is not None:
        a["ftp_anon"] = True
        a["ftp_files"] = ftp
        a["ftp_exposed"] = aj_shares.classify(ftp)
    a["findings"] = aj_audit.assess(a)
    return a


class Findings(unittest.TestCase):
    def test_share_contents_enrich_and_flag(self):
        a = audit_with([share("Backups", "read/write", [{"name": "passwords.txt"}, {"name": "photo.jpg"}])])
        f = {x["id"]: x for x in a["findings"]}
        self.assertIn("It contains", f["share_write"]["text"])
        self.assertEqual(f["share_sensitive"]["level"], "high")
        self.assertIn("passwords", f["share_sensitive"]["text"])

    def test_ordinary_share_has_no_sensitive_finding(self):
        a = audit_with([share("Public", "read", [{"name": "readme.txt"}])])
        self.assertNotIn("share_sensitive", {x["id"] for x in a["findings"]})
        self.assertIn("It contains documents", next(x["text"] for x in a["findings"] if x["id"] == "share_read"))

    def test_ftp_sensitive(self):
        a = audit_with(ftp=[{"name": "bank.pdf"}, {"name": "clip.mp4"}], ports=(21,))
        ids = {x["id"] for x in a["findings"]}
        self.assertIn("ftp_sensitive", ids)
        self.assertIn("including financial records", next(x["text"] for x in a["findings"] if x["id"] == "ftp_anon"))


class Scoring(unittest.TestCase):
    def dev(self, a):
        d = helpers.dev("192.168.1.9")
        d["audit"] = a
        return d

    def test_sensitive_share_costs_extra_and_fails_the_check(self):
        a = audit_with([share("Backups", "read", [{"name": "passwords.txt"}])])
        r = aj_score.security_report([self.dev(a)], None)
        pts = {i["id"]: i["points"] for i in r["issues"]}
        self.assertEqual(pts["share_read"], 8)
        self.assertEqual(pts["share_sensitive"], 15)
        self.assertEqual(r["score"], 100 - 8 - 15)
        self.assertIn("Get the sensitive files off", next(i["title"] for i in r["issues"] if i["id"] == "share_sensitive"))
        check = next(c for c in r["checks"] if "sensitive files" in c["label"])
        self.assertEqual(check["status"], "fail")

    def test_change_when_a_share_turns_sensitive(self):
        before = audit_with([share("Docs", "read", [{"name": "readme.txt"}])])
        after = audit_with([share("Docs", "read", [{"name": "readme.txt"}, {"name": "passwords.txt"}])])
        ch = aj_audit.audit_changes(before, after, "Office PC")
        self.assertTrue(any(k == "problem_new" and lvl == "high" and "passwords" in t for k, lvl, t in ch))


if __name__ == "__main__":
    unittest.main(verbosity=2)
