import datetime as dt
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from onboard.cli import main
from onboard.resolve import ResolveError, normalize, resolve, resolve_prefixes, risk_tier
from onboard.service_reference import INDEX_URL, ServiceReference, SourceError, check_url

HOST = "https://servicereference.us-east-1.amazonaws.com"


def action(name, *, perm=False, write=False, tagging=False, listing=False, resources=(), keys=()):
    return {"Name": name, "ActionConditionKeys": list(keys), "Resources": [{"Name": r} for r in resources],
            "Annotations": {"Properties": {"IsPermissionManagement": perm, "IsWrite": write,
                                           "IsTaggingOnly": tagging, "IsList": listing, "IsDataPlane": False}}}


# A small synthetic snapshot in the service reference's shape.
SERVICES = {
    "example": {
        "Name": "example", "Version": "v1.5",
        "Actions": [
            action("PutPolicy", perm=True, write=True, resources=["widget"]),
            action("CreateWidget", write=True, keys=["aws:RequestTag/${TagKey}", "aws:TagKeys"]),
            action("TagResource", write=True, tagging=True, resources=["widget"]),
            action("GetWidget", resources=["widget"]),
            action("ListWidgets", listing=True),
        ],
        "Resources": [{"Name": "widget", "ARNFormats": ["arn:${Partition}:example:${Region}:${Account}:widget/${Id}"]}],
        "ConditionKeys": [{"Name": "aws:TagKeys", "Types": ["ArrayOfString"]}],
        "Operations": [{"Name": "CreateWidget",
                        "AuthorizedActions": [{"Name": "CreateWidget", "Service": "example"}],
                        "SDK": [{"Name": "example", "Method": "create_widget", "Package": "Boto3"}]}],
    },
    "example-agent": {"Name": "example-agent", "Version": "v1.5", "Actions": [action("Invoke")]},
    "s3": {"Name": "s3", "Version": "v1.5", "Actions": [action("GetObject")]},
    "s3express": {"Name": "s3express", "Version": "v1.5", "Actions": [action("CreateSession")]},
    "s3tables": {"Name": "s3tables", "Version": "v1.5", "Actions": [action("GetTable")]},
}
INDEX = [{"service": p, "url": f"{HOST}/v1/{p}/{p}.json", "modified": 1792604700} for p in SERVICES]


def fake_fetch(url):
    if url == INDEX_URL:
        return json.dumps(INDEX).encode()
    prefix = url.rsplit("/", 1)[-1].removesuffix(".json")
    return json.dumps(SERVICES[prefix]).encode()


def reference():
    return ServiceReference(fake_fetch, clock=lambda: dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.timezone.utc))


class UrlGuardTest(unittest.TestCase):
    def test_allows_the_service_reference(self):
        check_url(INDEX_URL)
        check_url(f"{HOST}/v1/s3/s3.json")

    def test_refuses_other_hosts_and_schemes(self):
        for url in ("http://servicereference.us-east-1.amazonaws.com/",
                    "https://example.com/v1/s3/s3.json",
                    "https://servicereference.us-east-1.amazonaws.com.example.com/",
                    "https://user@servicereference.us-east-1.amazonaws.com/",  # pii-scan: allow (userinfo in a URL, not an email)
                    "https://servicereference.us-east-1.amazonaws.com:8443/",
                    "file:///etc/passwd"):
            with self.assertRaises(SourceError, msg=url):
                check_url(url)

    def test_index_entries_pointing_elsewhere_are_not_fetched(self):
        def fetch(url):
            if url == INDEX_URL:
                return json.dumps([{"service": "evil", "url": "https://example.com/evil.json"}]).encode()
            raise AssertionError(f"fetched {url}")
        with self.assertRaisesRegex(SourceError, "refusing"):
            ServiceReference(fetch).service("evil")

    def test_unexpected_shapes_fail_closed(self):
        with self.assertRaisesRegex(SourceError, "not a list"):
            ServiceReference(lambda url: b'{"service": "x"}').index()
        with self.assertRaisesRegex(SourceError, "not return JSON"):
            ServiceReference(lambda url: b"<html>").index()
        wrong = {**SERVICES["example"], "Name": "other"}
        ref = ServiceReference(lambda url: json.dumps(INDEX if url == INDEX_URL else wrong).encode())
        with self.assertRaisesRegex(SourceError, "unexpected shape"):
            ref.service("example")


class PrefixTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize("Amazon Bedrock"), "bedrock")
        self.assertEqual(normalize("AWS Lambda"), "lambda")
        self.assertEqual(normalize(" S3 "), "s3")

    def test_spans_keep_only_known_prefixes(self):
        prefixes, related = resolve_prefixes("Amazon S3", set(SERVICES))
        self.assertEqual(prefixes, ["s3", "s3express", "s3tables"])  # s3-object-lambda absent here
        self.assertEqual(related, [])

    def test_related_prefixes_are_proposed_not_included(self):
        prefixes, related = resolve_prefixes("example", set(SERVICES))
        self.assertEqual(prefixes, ["example"])
        self.assertEqual(related, ["example-agent"])

    def test_unknown_service(self):
        with self.assertRaisesRegex(ResolveError, "could not resolve"):
            resolve_prefixes("Amazon Nothing", set(SERVICES))


class ResolveTest(unittest.TestCase):
    def test_risk_tiers(self):
        tiers = {a["Name"]: risk_tier(a) for a in SERVICES["example"]["Actions"]}
        self.assertEqual(tiers, {"PutPolicy": "permission-management", "CreateWidget": "write",
                                 "TagResource": "tagging", "GetWidget": "read", "ListWidgets": "list"})

    def test_capability_profile(self):
        profile = resolve("example", reference())
        self.assertEqual(profile["prefixes"], ["example"])
        self.assertEqual(profile["related_prefixes_to_confirm"], ["example-agent"])
        svc = profile["services"][0]
        self.assertEqual([a["action"] for a in svc["actions"]],
                         ["example:CreateWidget", "example:GetWidget", "example:ListWidgets",
                          "example:PutPolicy", "example:TagResource"])
        self.assertEqual(svc["summary"]["actions_by_risk_tier"],
                         {"permission-management": 1, "write": 1, "tagging": 1, "read": 1, "list": 1})
        self.assertEqual(svc["operations"][0]["boto3"], ["example.create_widget"])
        source = profile["sources"][1]
        self.assertEqual((source["prefix"], source["version"], source["retrieved"]),
                         ("example", "v1.5", "2026-10-30T12:00:00Z"))
        self.assertTrue(profile["not_yet_assessed"])

    def test_profile_is_deterministic(self):
        self.assertEqual(json.dumps(resolve("s3", reference()), sort_keys=True),
                         json.dumps(resolve("s3", reference()), sort_keys=True))


class CliTest(unittest.TestCase):
    def test_resolve_from_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snapshot"
            snap.mkdir()
            (snap / "index.json").write_text(json.dumps(INDEX))
            for prefix, doc in SERVICES.items():
                (snap / f"{prefix}.json").write_text(json.dumps(doc))
            request = tmp / "request.json"
            request.write_text(json.dumps({
                "service": "Amazon S3", "maturity_tier": "Private Preview",
                "preview_accounts": ["111122223333"], "non_production_attested": True,
                "org_state": {}, "maker": "analyst-a", "checker": "analyst-b"}))
            out = tmp / "run"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["check-request", str(request)]), 0)
                self.assertEqual(main(["resolve", str(request), "--out", str(out), "--snapshot", str(snap)]), 0)
            profile = json.loads((out / "capability-profile.json").read_text())
            self.assertEqual(profile["prefixes"], ["s3", "s3express", "s3tables"])

    def test_invalid_request_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / "request.json"
            request.write_text("{}")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["check-request", str(request)]), 2)


if __name__ == "__main__":
    unittest.main()
