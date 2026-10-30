import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard.catalog import (
    CATALOG_URL, PINNED_INDEX, CatalogError, build_index, check_catalog_url, check_refs, fetch_index, load_index,
)
from onboard.cli import main
from onboard.controls import FindingsError, load_findings
from onboard.request import parse_request
from onboard.select import SelectError, select
from onboard.service_reference import SourceError

FIXTURES = Path(__file__).parent / "fixtures" / "athena"


def label(value, cls=None):
    return {"name": "label", "value": value, **({"class": cls} if cls else {})}


# A tiny catalog in OSCAL's shape: a control, an enhancement, a withdrawn enhancement.
OSCAL = {"catalog": {
    "metadata": {"title": "Electronic Version of NIST SP 800-53 Rev 5.2.0 Controls", "version": "5.2.0",
                 "last-modified": "2026-10-22T11:30:00.00000-00:00", "oscal-version": "1.2.3"},
    "groups": [{"id": "ac", "controls": [{
        "id": "ac-3", "title": "Access Enforcement", "props": [label("AC-03", "zero-padded"), label("AC-3")],
        "controls": [
            {"id": "ac-3.1", "title": "Restricted Access to Privileged Functions",
             "props": [label("AC-3(1)"), {"name": "status", "value": "withdrawn"}]},
            {"id": "ac-3.2", "title": "Dual Authorization", "props": [label("AC-03(02)", "zero-padded"),
                                                                     label("AC-3(2)")]},
        ]}]}]}}
RAW = json.dumps(OSCAL).encode()


def nist(cid, version="5.2.0"):
    return {"framework": "NIST-SP-800-53", "version": "r5", "id": cid, "catalog_version": version,
            "mapping_type": "inferred", "verification": "not-run"}


class BuildIndexTest(unittest.TestCase):
    def test_index(self):
        index = build_index(RAW, CATALOG_URL, "2026-10-30T15:05:00Z")
        self.assertEqual((index["version"], index["last_modified"]), ("5.2.0", "2026-10-22T11:30:00.00000-00:00"))
        self.assertEqual(index["source_sha256"], hashlib.sha256(RAW).hexdigest())
        self.assertEqual(index["controls"], {
            "ac-3": {"label": "AC-3", "title": "Access Enforcement", "withdrawn": False},
            "ac-3.1": {"label": "AC-3(1)", "title": "Restricted Access to Privileged Functions", "withdrawn": True},
            "ac-3.2": {"label": "AC-3(2)", "title": "Dual Authorization", "withdrawn": False},
        })

    def test_rejects_other_documents(self):
        with self.assertRaisesRegex(CatalogError, "not an OSCAL catalog"):
            build_index(b'{"profile": {}}', CATALOG_URL, "t")
        other = copy.deepcopy(OSCAL)
        other["catalog"]["metadata"]["title"] = "NIST SP 800-171 Rev 3"
        with self.assertRaisesRegex(CatalogError, "not the SP 800-53 catalog"):
            build_index(json.dumps(other).encode(), CATALOG_URL, "t")
        bad = copy.deepcopy(OSCAL)
        bad["catalog"]["groups"][0]["controls"][0]["id"] = "AC-3"
        with self.assertRaisesRegex(CatalogError, "unexpected control id"):
            build_index(json.dumps(bad).encode(), CATALOG_URL, "t")

    def test_fetch_uses_the_guarded_url(self):
        seen = []
        index = fetch_index(fetch=lambda url: seen.append(url) or RAW)
        self.assertEqual(seen, [CATALOG_URL])
        self.assertEqual(index["source_url"], CATALOG_URL)


class UrlGuardTest(unittest.TestCase):
    def test_allows_nist_oscal_content(self):
        check_catalog_url(CATALOG_URL)

    def test_refuses_anything_else(self):
        for url in (CATALOG_URL.replace("https://", "http://"),
                    "https://raw.githubusercontent.com/someone-else/oscal-content/main/catalog.json",
                    "https://example.com/usnistgov/oscal-content/catalog.json",
                    "https://user@raw.githubusercontent.com/usnistgov/oscal-content/x.json"):  # pii-scan: allow (URL userinfo)
            with self.assertRaises(SourceError, msg=url):
                check_catalog_url(url)


class PinnedIndexTest(unittest.TestCase):
    def test_pinned_catalog(self):
        index = load_index()
        self.assertEqual(index["version"], "5.2.0")
        self.assertEqual(index["source_url"], CATALOG_URL)
        self.assertEqual(index["source_sha256"], "64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb")
        self.assertEqual(len(index["controls"]), 1196)
        self.assertEqual(sum(c["withdrawn"] for c in index["controls"].values()), 182)

    def test_load_rejects_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            path.write_text('{"schema": "something-else"}')
            with self.assertRaisesRegex(CatalogError, "is not a nist-800-53-index/v1 document"):
                load_index(path)
            with self.assertRaisesRegex(CatalogError, "cannot read"):
                load_index(Path(tmp) / "missing.json")


class CheckRefsTest(unittest.TestCase):
    def setUp(self):
        self.index = load_index()

    def test_resolves_label_and_title(self):
        problems, refs = check_refs("X-C-01", [nist("ac-3"), nist("ac-2.1")], self.index)
        self.assertEqual(problems, [])
        self.assertEqual([(r["label"], r["title"]) for r in refs],
                         [("AC-3", "Access Enforcement"), ("AC-2(1)", "Automated System Account Management")])

    def test_ids_not_in_the_catalog_withdrawn_or_from_another_version(self):
        problems, _ = check_refs("X-C-01", [nist("ac-99"), nist("ac-3.1"), nist("ac-4", "5.1.1")], self.index)
        self.assertEqual(problems, [
            "X-C-01: ac-99 is not in NIST SP 800-53 5.2.0",
            "X-C-01: ac-3.1 (AC-3(1)) is withdrawn in NIST SP 800-53 5.2.0",
            "X-C-01: ac-4 names catalog version '5.1.1', but the pinned catalog is 5.2.0",
        ])

    def test_other_frameworks_pass_through(self):
        cri = {"framework": "CRI-Profile", "version": "v2.2", "id": "DE.CM-03.01"}
        problems, refs = check_refs("X-C-01", [cri, nist("au-12")], self.index)
        self.assertEqual((problems, refs[0]), ([], cri))


class FindingsAndSelectTest(unittest.TestCase):
    def findings(self):
        return json.loads((FIXTURES / "findings.json").read_text())

    def test_findings_need_catalog_form_ids(self):
        f = self.findings()
        f["candidates"][0]["framework_refs"][0]["id"] = "SC-7"  # cited from memory, display form
        with self.assertRaisesRegex(FindingsError, "needs a NIST catalog id"):
            load_findings(f)

    def test_findings_need_a_nist_reference(self):
        f = self.findings()
        f["candidates"][0]["framework_refs"] = [{"framework": "CRI-Profile", "version": "v2.2", "id": "DE.CM-03.01",
                                                 "mapping_type": "aws-mapped", "verification": "verified"}]
        with self.assertRaisesRegex(FindingsError, "at least one NIST-SP-800-53 reference"):
            load_findings(f)

    def test_select_refuses_ids_the_catalog_does_not_have(self):
        f = self.findings()
        cand = next(c for c in f["candidates"] if c["control_id"] == "ATH-H-05")
        cand["framework_refs"][0]["id"] = "sc-99"
        request = parse_request(json.loads((FIXTURES / "request-private-preview.json").read_text()))
        # Checked for every candidate, even one outside the requested tier.
        with self.assertRaisesRegex(SelectError, "ATH-H-05: sc-99 is not in NIST SP 800-53 5.2.0"):
            select(load_findings(f), request, load_index())


class CatalogCliTest(unittest.TestCase):
    def test_build_from_a_local_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "catalog.json", Path(tmp) / "index.json"
            source.write_bytes(RAW)
            with redirect_stdout(io.StringIO()) as stdout:
                code = main(["catalog", "--source", str(source), "--retrieved", "2026-10-30T15:05:00Z", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn("3 controls and enhancements, 1 withdrawn", stdout.getvalue())
            self.assertEqual(load_index(out)["retrieved"], "2026-10-30T15:05:00Z")

    def test_pinned_index_path(self):
        self.assertEqual(PINNED_INDEX.parts[-2:], ("catalogs", "nist-sp-800-53-rev5.json"))


if __name__ == "__main__":
    unittest.main()
