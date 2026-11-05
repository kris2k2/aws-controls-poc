"""Report (ADR-0010): the visual summary of a run, on Athena through the real pipeline."""

import copy
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard import report
from onboard.cli import main
from tests.test_athena_acceptance import SNAPSHOT
from tests.test_athena_journey import FIXTURES, load


def build(tmp: Path, review=True) -> Path:
    """Athena at Private Preview: resolve, select, generate, verify and (optionally) review."""
    request, run = FIXTURES / "request-private-preview.json", tmp / "athena"
    steps = [["resolve", request, "--out", run, "--snapshot", SNAPSHOT],
             ["select", request, "--findings", FIXTURES / "findings.json", "--out", run],
             ["generate", request, "--run", run], ["verify", request, "--run", run]]
    if review:
        steps.append(["review", request, "--run", run])
    with redirect_stdout(io.StringIO()):
        for step in steps:
            main([str(s) for s in step])
    return run


class ReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = build(Path(cls.tmp.name))
        cls.files = report.load(cls.run_dir)
        cls.html = report.render(cls.files)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_it_summarizes_the_service_threats_guardrails_and_review(self):
        for text in ("<h1>Amazon Athena</h1>", "Private Preview", "API surface by risk tier", "Threat vectors",
                     "Data exfiltration", "Privilege escalation", "Implemented guardrails", "scp-athena-guardrails",
                     "Release review", "On hold", "AR-05 accepted risk", "Sources and integrity"):
            self.assertIn(text, self.html)
        for cid in self.files["controls"]:
            self.assertIn(f"<code>{cid}</code>", self.html)

    def test_every_athena_objective_has_a_threat_vector(self):
        objectives = {c["objective"] for c in load("findings.json")["candidates"]}
        self.assertEqual(objectives - set(report.OBJECTIVES), set())
        self.assertNotIn("Other", [v["category"] for v in report.threats(self.files)])

    def test_coverage_is_what_the_run_generated(self):
        vectors = {v["threat"]: v for v in report.threats(self.files)}
        preview = vectors[report.OBJECTIVES["preview-accounts"][1]]
        self.assertEqual(preview["coverage"], "prevented")
        self.assertEqual(preview["controls"][0]["proof"]["result"], "pass")
        self.assertEqual(report.coverage({"sentinel": {"status": "generated"}, "config": {"status": "pending"}}),
                         ["plan-time"])
        self.assertEqual(report.coverage({"scp": {"status": "not_deployed"}}), ["gap"])

    def test_it_is_self_contained_and_deterministic(self):
        self.assertIn("default-src 'none'", self.html)
        self.assertNotRegex(self.html, r"<script|<link|<img|@import|url\(")
        self.assertEqual(report.render(report.load(self.run_dir)), self.html)

    def test_run_values_are_escaped_and_only_https_is_linked(self):
        files = copy.deepcopy(self.files)
        record = files["controls"]["ATH-C-02"]
        record["title"] = '<script>alert("x")</script>'
        record["objective"] = "made-up"
        files["capability-profile"]["sources"].append({"source": "x", "url": "javascript:alert(1)", "retrieved": "y"})
        html = report.render(files)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", html)
        self.assertNotIn('href="javascript:', html)
        self.assertIn("Other", [report.CATEGORIES[v["category"]][0] for v in report.threats(files)])

    def test_missing_stages_are_said_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = build(Path(tmp), review=False)
            (run / "verification.json").unlink()
            html = report.render(report.load(run))
            self.assertIn("Verify hasn&#x27;t run", html)
            self.assertIn("Review hasn't run on this run.", html)
            (run / "generation.json").unlink()
            with self.assertRaises(report.ReportError):
                report.load(run)

    def test_the_cli_writes_it(self):
        out = Path(self.tmp.name) / "elsewhere" / "athena.html"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["report", "--run", str(self.run_dir), "--out", str(out)]), 0)
        self.assertEqual(out.read_text(encoding="utf-8"), self.html)
        self.assertTrue(re.search(r"<title>Amazon Athena security report</title>", self.html))


if __name__ == "__main__":
    unittest.main()
