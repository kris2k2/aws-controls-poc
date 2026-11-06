"""Assess (ADR-0007) and its Control Catalog client.

Offline: the catalog is the synthetic snapshot in
tests/fixtures/control-catalog/athena-synthetic/, and the HTTPS transport is
exercised against a fake opener. The SigV4 vectors were computed with
botocore 1.43.125 (SigV4Auth, signing name controlcatalog, ca-central-1, the
clock fixed at 2026-11-05T12:00:00Z) as an independent oracle; botocore is
not a dependency.
"""

import datetime as dt
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onboard import control_catalog as cc
from onboard.assess import AssessError, assess, nist_id
from onboard.catalog import load_index
from onboard.cli import main
from onboard.request import parse_request
from onboard.service_reference import SourceError
from tests.test_athena_acceptance import SNAPSHOT

FIXTURES = Path(__file__).parent / "fixtures"
ATHENA = FIXTURES / "athena"
CATALOG_SNAPSHOT = FIXTURES / "control-catalog" / "athena-synthetic"
NIST = load_index()
CREDS = cc.Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
SH_FILTER = {"Filter": {"Implementations": {"Types": ["AWS::SecurityHub::SecurityControl"]}}}
NOW = dt.datetime(2026, 11, 5, 12, 0, 0)


def load(path):
    return json.loads(Path(path).read_text())


def run_assess(tier="private-preview", overlay=None, transport=None):
    request = parse_request(load(ATHENA / f"request-{tier}.json"))
    profile = {"service": "Amazon Athena", "prefixes": ["athena"]}
    catalog = cc.ControlCatalog(transport or cc.snapshot_transport(CATALOG_SNAPSHOT))
    return assess(request, profile, catalog, NIST,
                  overlay=load(ATHENA / "overlay.json") if overlay is None else overlay,
                  source={"mode": "snapshot", **cc.snapshot_metadata(CATALOG_SNAPSHOT)})


class SigV4Test(unittest.TestCase):
    def sign(self, creds):
        return cc.sign("POST", cc.HOST, "/list-controls", {"maxResults": "100", "nextToken": "abc/def=="},
                       cc.body_bytes(SH_FILTER), creds, NOW)

    def test_signature_matches_botocore(self):
        headers = self.sign(CREDS)
        self.assertEqual(headers["X-Amz-Date"], "20261105T120000Z")
        self.assertEqual(headers["Authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261105/ca-central-1/controlcatalog/aws4_request, "
                         "SignedHeaders=content-type;host;x-amz-date, "
                         "Signature=1087402a363fea3fcb47a0e05bdfa0456f412c7bf03d3e29d7f64702f24aff58")

    def test_session_token_is_signed(self):
        headers = self.sign(cc.Credentials(CREDS.access_key, CREDS.secret_key, "EXAMPLESESSIONTOKEN"))
        self.assertEqual(headers["X-Amz-Security-Token"], "EXAMPLESESSIONTOKEN")
        self.assertIn("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, "
                      "Signature=898ea36526a47587b720680c2a4f9e9efcfecbc288a0a9d29545ae94a1f7b1cc",
                      headers["Authorization"])


class ClientTest(unittest.TestCase):
    def test_only_the_home_region_host_over_https(self):
        cc.check_url(f"https://{cc.HOST}/list-controls")
        userinfo = "user:pw" + "@"
        for url in (f"http://{cc.HOST}/list-controls",
                    "https://controlcatalog.us-east-1.amazonaws.com/list-controls",
                    f"https://{cc.HOST}.example.com/",
                    f"https://{userinfo}{cc.HOST}/",
                    f"https://{cc.HOST}:8443/"):
            with self.subTest(url=url), self.assertRaises(SourceError):
                cc.check_url(url)

    def test_missing_credentials_fail_closed_without_values(self):
        with self.assertRaises(SourceError) as ctx:
            cc.credentials_from_env({"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE"})
        self.assertIn("AWS_SECRET_ACCESS_KEY", str(ctx.exception))
        self.assertNotIn("AKIDEXAMPLE", str(ctx.exception))

    def test_secrets_stay_out_of_repr(self):
        text = repr(cc.Credentials("AKIDEXAMPLE", "secret-value", "token-value"))
        self.assertNotIn("secret-value", text)
        self.assertNotIn("token-value", text)

    def test_only_read_only_operations(self):
        call = cc.http_transport(CREDS, clock=lambda: NOW)
        for operation in ("GetControl", "EnableControl", "ListDomains"):
            with self.subTest(operation=operation), self.assertRaises(SourceError):
                call(operation, {}, {})

    def fake_opener(self, body=b'{"Controls": []}', error=None):
        sent = []

        class Response(io.BytesIO):
            def geturl(self):
                return sent[-1].full_url

        class Opener:
            def open(self, request, timeout):
                sent.append(request)
                if error:
                    raise error
                return Response(body)

        return sent, mock.patch("urllib.request.build_opener", return_value=Opener())

    def test_a_call_is_signed_and_goes_only_to_the_catalog(self):
        sent, patch = self.fake_opener()
        with patch:
            call = cc.http_transport(CREDS, clock=lambda: NOW)
            self.assertEqual(call("ListControls", {"maxResults": "100"}, SH_FILTER), {"Controls": []})
        request = sent[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, f"https://{cc.HOST}/list-controls?maxResults=100")
        self.assertEqual(request.data, cc.body_bytes(SH_FILTER))
        self.assertTrue(request.get_header("Authorization").startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"))
        self.assertNotIn(CREDS.secret_key, json.dumps(request.header_items()))

    def test_errors_name_the_aws_error_not_the_request(self):
        error = urllib.error.HTTPError(f"https://{cc.HOST}/list-controls", 403, "Forbidden",
                                       {"x-amzn-ErrorType": "AccessDeniedException:http://internal"},
                                       io.BytesIO(b'{"message": "not authorized"}'))
        _, patch = self.fake_opener(error=error)
        with patch, self.assertRaises(SourceError) as ctx:
            cc.http_transport(CREDS, clock=lambda: NOW)("ListControls", {}, SH_FILTER)
        self.assertIn("HTTP 403 AccessDeniedException not authorized", str(ctx.exception))
        self.assertNotIn("Signature", str(ctx.exception))

    def test_pagination_follows_tokens_and_stops_on_a_repeat(self):
        controls = cc.ControlCatalog(cc.snapshot_transport(CATALOG_SNAPSHOT)).list_controls(
            "AWS::SecurityHub::SecurityControl")
        self.assertEqual(len(controls), 6)
        looping = cc.ControlCatalog(lambda op, q, b: {"Controls": [], "NextToken": "again"})
        with self.assertRaises(SourceError):
            looping.list_controls("AWS::SecurityHub::SecurityControl")

    def test_snapshot_refuses_unknown_requests_and_path_tricks(self):
        replay = cc.snapshot_transport(CATALOG_SNAPSHOT)
        with self.assertRaises(SourceError):
            replay("ListControls", {"maxResults": "100"}, {"Filter": {}})
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "index.json").write_text(json.dumps({"schema": cc.SNAPSHOT_SCHEMA, "responses": [
                {"operation": "ListControls", "query": {}, "body": {}, "file": "../outside.json"}]}))
            with self.assertRaises(SourceError):
                cc.snapshot_transport(Path(tmp))

    def test_a_recording_replays_and_holds_no_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            inner = cc.snapshot_transport(CATALOG_SNAPSHOT)
            recorder = cc.ControlCatalog(cc.recording_transport(inner, Path(tmp), clock=lambda: NOW))
            recorded = recorder.list_controls("AWS::SecurityHub::SecurityControl")
            replayed = cc.ControlCatalog(cc.snapshot_transport(Path(tmp))).list_controls(
                "AWS::SecurityHub::SecurityControl")
            self.assertEqual(recorded, replayed)
            text = "".join(p.read_text() for p in Path(tmp).iterdir())
            self.assertNotIn("AKID", text)
            self.assertFalse(cc.snapshot_metadata(Path(tmp))["synthetic"])


class AssessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_assess()
        cls.findings, cls.report = cls.result["findings"], cls.result["assessment"]
        cls.by_id = {c["control_id"]: c for c in cls.findings["candidates"]}

    def test_every_source_is_counted(self):
        self.assertEqual(self.findings["service"], "athena")
        self.assertEqual(self.report["counts"], {"organization-baseline": 11, "derived": 1,
                                                 "control-catalog": 3, "analyst-overlay": 12})
        origins = {c["control_id"]: c["origin"] for c in self.report["candidates"]}
        self.assertEqual(origins["ORG-C-04"], "organization-baseline")
        self.assertEqual(origins["ATH-C-01"], "derived")
        self.assertEqual(origins["ATH-C-03"], "analyst-overlay")

    def test_the_preview_restriction_is_derived_from_the_contract(self):
        c = self.by_id["ATH-C-01"]
        self.assertEqual(c["guardrail"]["actions"], ["athena:*"])
        self.assertEqual(c["until_tier"], "Private Preview")
        self.assertEqual(c["title"], "Athena only in the authorized preview accounts")

    def test_security_hub_controls_carry_aws_severity_and_mappings(self):
        logging = self.by_id["ATH-SH-04"]
        self.assertEqual((logging["class"], logging["severity"], logging["severity_source"]),
                         ("Supervision", "Medium", "control-catalog"))
        self.assertEqual([r["id"] for r in logging["framework_refs"]], ["ac-2.4", "au-12"])
        self.assertEqual({r["mapping_type"] for r in logging["framework_refs"]}, {"aws-mapped"})
        self.assertEqual(logging["mapping_problems"], ["'ZZ-99' (NIST-SP-800-53-r5) is not a control in "
                                                       f"NIST SP 800-53 {NIST['version']}"])
        self.assertEqual(logging["implementations"]["config"]["status"], "planned")
        self.assertNotIn("guardrail", logging)
        for cid in ("ATH-SH-02", "ATH-SH-03"):
            self.assertEqual((self.by_id[cid]["class"], self.by_id[cid]["severity"]), ("Hardening", "Low"))
        self.assertEqual([r["id"] for r in self.by_id["ATH-SH-03"]["framework_refs"]], ["cm-8"])  # deduplicated

    def test_a_synthetic_snapshot_is_never_called_verified(self):
        for cid in ("ATH-SH-02", "ATH-SH-03", "ATH-SH-04"):
            c = self.by_id[cid]
            self.assertEqual({x["verification"] for x in c["citations"] + c["framework_refs"]}, {"unverifiable"})

    def test_what_is_not_imported_is_listed_with_the_reason(self):
        source = self.report["sources"]["control_catalog"]
        skipped = {s["identifier"]: s["reason"] for s in source["skipped"]}
        self.assertIn("no NIST SP 800-53 Rev 5 mapping", skipped["Athena.99"])
        self.assertIn("PROACTIVE", skipped["Athena.98"])
        self.assertNotIn("ATH-SH-01", self.by_id)  # S3.1 governs S3, not Athena
        self.assertEqual(source["frameworks_seen"], ["FedRAMP-r4", "NIST-SP-800-53-r5"])
        self.assertEqual(source["nist_framework_names"], ["NIST-SP-800-53-r5"])
        self.assertTrue(source["synthetic"])

    def test_nist_items_are_converted_to_catalog_form(self):
        for item, expected in (("AC-3", "ac-3"), ("AC-2(1)", "ac-2.1"), ("ac-2 (12)", "ac-2.12"),
                               ("SC-7.5", "sc-7.5"), ("AC", None), ("AC-3(a)", None)):
            with self.subTest(item=item):
                self.assertEqual(nist_id(item), expected)

    def test_the_overlay_adds_but_never_replaces(self):
        overlay = load(ATHENA / "overlay.json")
        for cid in ("ORG-C-01", "ATH-C-01", "ATH-SH-04"):
            bad = {**overlay, "candidates": overlay["candidates"] + [{**overlay["candidates"][0], "control_id": cid}]}
            with self.subTest(cid=cid), self.assertRaises(AssessError):
                run_assess(overlay=bad)
        with self.assertRaises(AssessError):
            run_assess(overlay={**overlay, "service": "bedrock"})

    def test_without_an_overlay_the_findings_still_validate(self):
        result = run_assess(overlay={"schema": "findings-overlay/v1", "service": "athena", "candidates": []})
        self.assertEqual(result["assessment"]["counts"]["analyst-overlay"], 0)
        self.assertIsNone(result["assessment"]["sources"]["analyst_overlay"])

    def test_the_same_inputs_give_the_same_findings(self):
        self.assertEqual(run_assess()["assessment"]["findings_sha256"], self.report["findings_sha256"])


class AssessedJourneyTest(unittest.TestCase):
    """Athena through every tier from assessed findings: the outcomes of the hand-written journey."""

    def test_the_three_tiers_through_the_cli(self):
        expected = {"private-preview": 13, "contained": 20, "hardened": 26}
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            tmp, registry = Path(tmp), None
            for tier, count in expected.items():
                data = load(ATHENA / f"request-{tier}.json")
                if registry is not None:
                    data["control_registry"] = registry
                request = tmp / f"{tier}.json"
                request.write_text(json.dumps(data))
                run, hand = tmp / tier, tmp / f"hand-{tier}"
                self.assertEqual(main(["resolve", str(request), "--out", str(run), "--snapshot", str(SNAPSHOT)]), 0)
                self.assertEqual(main(["assess", str(request), "--run", str(run),
                                       "--overlay", str(ATHENA / "overlay.json"),
                                       "--control-catalog-snapshot", str(CATALOG_SNAPSHOT)]), 0)
                self.assertEqual(main(["select", str(request), "--findings", str(run / "findings.json"),
                                       "--out", str(run)]), 0)
                self.assertEqual(main(["generate", str(request), "--run", str(run)]), 0)
                self.assertEqual(main(["verify", str(request), "--run", str(run)]), 0)
                self.assertEqual(len(load(run / "selection.json")["controls"]), count)
                # The guardrails are exactly those of the reviewed, hand-written findings.
                self.assertEqual(main(["select", str(request), "--findings", str(ATHENA / "findings.json"),
                                       "--out", str(hand)]), 0)
                self.assertEqual(main(["generate", str(request), "--run", str(hand)]), 0)
                policies = sorted(p.name for p in (run / "org-policies").glob("*.json"))
                self.assertEqual(policies, sorted(p.name for p in (hand / "org-policies").glob("*.json")))
                for name in policies:
                    self.assertEqual((run / "org-policies" / name).read_text(),
                                     (hand / "org-policies" / name).read_text())
                registry = load(run / "registry.json")

    def test_assess_needs_the_capability_profile(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["assess", str(ATHENA / "request-private-preview.json"), "--run", tmp,
                                   "--control-catalog-snapshot", str(CATALOG_SNAPSHOT)]), 2)

    def test_a_live_run_without_credentials_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()) as err, mock.patch.dict("os.environ", {}, clear=True):
            request = str(ATHENA / "request-private-preview.json")
            self.assertEqual(main(["resolve", request, "--out", tmp, "--snapshot", str(SNAPSHOT)]), 0)
            self.assertEqual(main(["assess", request, "--run", tmp]), 2)
            self.assertIn("needs AWS credentials", err.getvalue())
            self.assertFalse(Path(tmp, "findings.json").exists())


if __name__ == "__main__":
    unittest.main()
