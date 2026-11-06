import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compare_advisories as evaluate


def record(cve="CVE-2026-12345"):
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
            "containers": {"cna": {
                "title": "Buffer overflow",
                "descriptions": [{"lang": "en", "value": "A remote attacker overflows a buffer."}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-120"}]}],
                "impacts": [{"capecId": "CAPEC-10", "descriptions": [{"lang": "en", "value": "Buffer overflow"}]}],
                "affected": [{"vendor": "Example", "product": "Widget", "versions": [
                    {"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "semver"}]}],
                "references": [{"url": "https://github.com/example/widget/commit/abcdef1234567"}],
                "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                             "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
            }}}


class FieldComparisonTests(unittest.TestCase):
    def test_identical_record(self):
        result = evaluate.compare_records(record(), record())
        self.assertEqual(result["field_differences"], [])
        self.assertEqual(result["sets"]["cwe"]["f1"], 1)
        self.assertEqual(result["text"]["descriptions"]["by_language"]["en"]["cosine_similarity"], 1)
        self.assertEqual(result["cvss"]["comparisons"][0]["absolute_score_error"], 0)
        self.assertEqual(result["text"]["impacts"]["by_language"]["en"]["original"], "Buffer overflow")

    def test_missing_data_is_not_false_agreement_or_false_positive(self):
        empty = evaluate.set_comparison([], [])
        self.assertIsNone(empty["exact_match"])
        self.assertIsNone(empty["f1"])
        added = evaluate.set_comparison([], ["CWE-120"])
        self.assertEqual(added["presence"], "generated_only")
        self.assertIsNone(added["precision"])
        self.assertIsNone(added["jaccard"])
        missing = evaluate.set_comparison(["CWE-120"], [])
        self.assertEqual(missing["recall"], 0)
        self.assertEqual(missing["f1"], 0)

    def test_set_counts_and_reference_normalization(self):
        diff = evaluate.set_comparison(["CWE-120", "CWE-787"], ["CWE-120", "CWE-79", "CWE-79"])
        self.assertEqual(diff["precision"], .5)
        self.assertEqual(diff["missing_from_generated"], ["CWE-787"])
        self.assertEqual(diff["added_in_generated"], ["CWE-79"])
        url = "https://github.com/example/widget/commit/abcdef1234567"
        self.assertEqual(evaluate.reference_url(url + ".patch#diff-1"), url)
        self.assertNotEqual(evaluate.reference_url("https://example.org/?id=1"), evaluate.reference_url("https://example.org/?id=2"))

    def test_versions_stay_scoped_and_keep_range_semantics(self):
        original, generated = record(), record()
        generated["containers"]["cna"]["affected"][0]["versions"][0]["lessThanOrEqual"] = "2.0"
        del generated["containers"]["cna"]["affected"][0]["versions"][0]["lessThan"]
        result = evaluate.compare_records(original, generated)
        self.assertFalse(result["sets"]["versions"]["exact_match"])
        self.assertTrue(result["sets"]["products"]["exact_match"])
        generated["containers"]["cna"]["affected"][0]["product"] = "Another product"
        self.assertFalse(evaluate.compare_records(original, generated)["sets"]["products"]["exact_match"])

    def test_language_missing_and_no_translation_assumption(self):
        result = evaluate.text_comparison([{"lang": "fr", "value": "Une erreur distante"}],
                                         [{"lang": "en", "value": "A remote error"}])
        self.assertIsNone(result["by_language"]["fr"]["cosine_similarity"])
        self.assertEqual(result["by_language"]["en"]["presence"], "generated_only")

    def test_cvss_versions_and_scenarios_not_cross_compared(self):
        original, generated = record(), record()
        cna = generated["containers"]["cna"]
        cna["metrics"] = [{"cvssV4_0": {"version": "4.0", "baseScore": 9.2}}]
        result = evaluate.compare_records(original, generated)["cvss"]
        self.assertTrue(all(r["status"] == "no_matching_scope" for r in result["comparisons"]))
        cna["metrics"] = copy.deepcopy(original["containers"]["cna"]["metrics"])
        cna["metrics"][0]["scenarios"] = [{"lang": "en", "value": "LOCAL ONLY"}]
        self.assertTrue(all(r["status"] == "no_matching_scope" for r in evaluate.compare_records(original, generated)["cvss"]["comparisons"]))

    def test_cvss_multiple_scores_are_ambiguous_not_arbitrarily_selected(self):
        original, generated = record(), record()
        original["containers"]["cna"]["metrics"] *= 2
        result = evaluate.compare_records(original, generated)["cvss"]["comparisons"][0]
        self.assertEqual(result["status"], "ambiguous")
        self.assertNotIn("score_delta", result)

    def test_cvss_vector_differences_and_signed_score_delta(self):
        original, generated = record(), record()
        cvss = generated["containers"]["cna"]["metrics"][0]["cvssV3_1"]
        cvss.update(baseScore=8.8, vectorString=cvss["vectorString"].replace("AV:N", "AV:L"))
        row = evaluate.compare_records(original, generated)["cvss"]["comparisons"][0]
        self.assertAlmostEqual(row["score_delta"], -1)
        self.assertFalse(row["vector_metrics"]["AV"]["match"])

    def test_ssvc_and_adp_remain_distinct(self):
        original, generated = record(), record()
        metric = {"other": {"type": "ssvc", "content": {"version": "2.0.3", "role": "Supplier", "options": [{"Exploitation": "none"}]}}}
        for r in (original, generated):
            r["containers"]["cna"]["metrics"].append(copy.deepcopy(metric))
        original["containers"]["adp"] = [{"metrics": [{"cvssV4_0": {"version": "4.0", "baseScore": 7}}]}]
        result = evaluate.compare_records(original, generated)
        self.assertTrue(result["ssvc"]["comparisons"][0]["options"]["exact_match"])
        self.assertEqual(len(result["cvss"]["original"]), 1)
        self.assertEqual(len(result["adp"]["original"]), 1)
        supplementary = result["supplementary_metrics"][0]
        self.assertEqual(supplementary["source"], "containers.adp[0]")
        self.assertEqual(supplementary["cvss"]["original"][0]["version"], "4.0")

    def test_summary_weights_cves_equally_and_excludes_missing_reference(self):
        def report(cve, original, generated):
            return {"status": "compared", "cve_id": cve, "llm": {"status": "disabled"},
                    "comparison": evaluate.compare_records(original, generated)}
        original, generated = record(), record()
        generated["containers"]["cna"]["problemTypes"] = []
        reports = [report("CVE-2026-12345", original, generated)] * 2
        reports += [report("CVE-2026-12346", original, original)]
        summary = evaluate.summarize(reports)
        stats = summary["statistics"]["sets.cwe.recall"]
        self.assertEqual(stats["count"], 3)
        self.assertAlmostEqual(stats["mean"], 1 / 3)
        self.assertEqual(stats["cve_macro_mean"], .5)
        self.assertNotIn("sets.credits.f1", summary["statistics"])
        self.assertEqual(summary, evaluate.summarize([evaluate.summary_row(r) for r in reports]))


class FetchAndReviewTests(unittest.TestCase):
    def test_cache_roundtrip_integrity_and_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            client = evaluate.Originals(cache, "https://db.gcve.eu/api/vulnerability")
            with patch.object(evaluate, "request_json", return_value=record()) as request:
                original, meta = client.get("CVE-2026-12345")
                client.get("CVE-2026-12345")
                self.assertEqual(request.call_count, 1)
                self.assertTrue(meta["source_url"].endswith("/CVE-2026-12345"))
            offline = evaluate.Originals(cache, client.api_base, offline=True)
            self.assertEqual(offline.get("CVE-2026-12345")[0], original)
            saved = cache / "CVE-2026-12345.json"
            value = json.loads(saved.read_text())
            value["record"]["containers"]["cna"]["title"] = "modified"
            evaluate.write_json(saved, value)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                evaluate.Originals(cache, client.api_base).get("CVE-2026-12345")
            with patch.object(evaluate, "request_json", return_value=record()):
                self.assertEqual(evaluate.Originals(cache, client.api_base, refresh=True).get("CVE-2026-12345")[0], original)

    def test_transient_retries_but_no_retry_on_missing_or_denied(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluate.time, "sleep"):
            for code, count in [(503, 3), (429, 3), (404, 1), (403, 1)]:
                with self.subTest(code=code), patch.object(evaluate, "request_json", side_effect=HTTPError("https://example.org", code, "error", {}, None)) as request:
                    with self.assertRaises(HTTPError):
                        evaluate.Originals(Path(tmp), "https://example.org").get("CVE-2026-12345")
                    self.assertEqual(request.call_count, count)

    def test_invalid_original_id_and_empty_response_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for response in ({}, record("CVE-2026-99999")):
                with patch.object(evaluate, "request_json", return_value=response), self.assertRaises(ValueError):
                    evaluate.Originals(Path(tmp), "https://example.org").get("CVE-2026-12345")

    def test_ollama_schema_evidence_and_context_limits(self):
        fields = evaluate.REVIEW_SCHEMA["properties"]["assessments"]["items"]["properties"]
        review = {"assessments": [{"dimension": dimension, "verdict": "supported", "explanation": "Same title",
                   "original_evidence": "Buffer overflow", "generated_evidence": "invented quote"}
                   for dimension in fields["dimension"]["enum"]], "limitations": ["Incomplete reference"]}
        with patch.object(evaluate, "request_json", return_value={"message": {"content": json.dumps(review)}}) as request:
            result = evaluate.ollama_review(record(), record(), "http://localhost:11434", "test-model", 30, 100000)
            finding = result["review"]["assessments"][0]
            self.assertTrue(finding["original_evidence_verified"])
            self.assertFalse(finding["generated_evidence_verified"])
            payload = request.call_args.args[2]
            self.assertFalse(payload["stream"])
            self.assertIn("untrusted evidence", payload["messages"][0]["content"])
        with self.assertRaisesRegex(ValueError, "no silent truncation"):
            evaluate.ollama_review(record(), record(), "http://localhost:11434", "test-model", 30, 1)
        review["assessments"] = review["assessments"][:1]
        with self.assertRaisesRegex(ValueError, "each dimension"):
            evaluate.validate_review(review)


class CLITests(unittest.TestCase):
    def test_offline_multiple_runs_errors_and_no_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs, originals, output = root / "inputs", root / "originals", root / "output"
            original = record()
            evaluate.write_json(originals / "CVE-2026-12345.json", original)
            for run in ("run_001", "run_002"):
                evaluate.write_json(inputs / "CVE-2026-12345" / "repo_commit" / run / "CVE-2026-12345.cve.json", original)
            broken = inputs / "run_broken/CVE-2026-99999.cve.json"
            broken.parent.mkdir(parents=True)
            broken.write_text('{"partially_written":')
            before = {str(p): p.read_bytes() for p in inputs.rglob("*.json")}
            cmd = [sys.executable, str(Path(evaluate.__file__)), "--results-dir", str(inputs), "--output-dir", str(output),
                   "--originals-dir", str(originals), "--offline"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            summary = evaluate.read_json(output / "summary.json")
            self.assertEqual(summary["statuses"], {"compared": 2, "error": 1})
            self.assertEqual(summary["compared_cve_count"], 1)
            self.assertEqual(len(list((output / "comparisons").rglob("*.json"))), 3)
            self.assertEqual(before, {str(p): p.read_bytes() for p in inputs.rglob("*.json")})
            # A filtered rerun replaces the summary; stale error reports aren't counted.
            result = subprocess.run(cmd + ["--cve", "CVE-2026-12345", "--limit", "1"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(evaluate.read_json(output / "summary.json")["report_count"], 1)

    def test_no_files_and_output_overlap_are_cli_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            for args in (["--results-dir", tmp, "--output-dir", tmp],
                         ["--results-dir", tmp, "--output-dir", tmp + "-outside"]):
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    evaluate.main(args)
                self.assertEqual(error.exception.code, 2)

    def test_llm_failure_preserves_statistics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evaluate.write_json(root / "inputs/CVE-2026-12345.cve.json", record())
            evaluate.write_json(root / "originals/CVE-2026-12345.json", record())
            with patch.object(evaluate, "ollama_review", side_effect=ValueError("bad model JSON")):
                status = evaluate.main(["--results-dir", str(root / "inputs"), "--output-dir", str(root / "out"),
                    "--originals-dir", str(root / "originals"), "--ollama-model", "missing-model"])
            self.assertEqual(status, 1)
            summary = evaluate.read_json(root / "out/summary.json")
            self.assertEqual(summary["statuses"], {"llm_error": 1})
            self.assertEqual(summary["statistics"]["sets.cwe.recall"]["mean"], 1)

    def test_rejected_original_and_missing_original_produce_error_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for cve in ("CVE-2026-12345", "CVE-2026-12346"):
                evaluate.write_json(root / "inputs" / f"{cve}.cve.json", record(cve))
            rejected = record()
            rejected["cveMetadata"]["state"] = "REJECTED"
            evaluate.write_json(root / "originals/CVE-2026-12345.json", rejected)
            status = evaluate.main(["--results-dir", str(root / "inputs"), "--output-dir", str(root / "out"),
                                   "--originals-dir", str(root / "originals"), "--offline"])
            self.assertEqual(status, 1)
            summary = evaluate.read_json(root / "out/summary.json")
            self.assertEqual(summary["statuses"], {"error": 2})
            self.assertEqual(summary["statistics"], {})
            report = evaluate.read_json(root / "out/comparisons/CVE-2026-12345.cve.comparison.json")
            self.assertIn("not a PUBLISHED", report["error"]["message"])
            self.assertNotIn("comparison", report)


if __name__ == "__main__":
    unittest.main()
