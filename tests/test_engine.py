import tempfile
import unittest
from pathlib import Path

import main


class AnalysisEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        main.DB_PATH = Path(self.temp.name) / "test.db"
        main.init_db()

    def tearDown(self):
        self.temp.cleanup()

    def test_demo_scenarios_rank_evidence_supported_categories(self):
        expected = {
            "demo-pool": "Connection pool exhaustion",
            "demo-deploy": "Deployment regression",
            "demo-resource": "Resource exhaustion",
            "demo-dependency": "Dependency failure",
            "demo-unknown": "Unknown",
        }
        with main.db() as connection:
            for incident_id, category in expected.items():
                incident = main.fetch_incident(connection, incident_id)
                report = main.analyze_incident(connection, incident, 10, 10)
                if category == "Unknown":
                    self.assertEqual(report["status"], "Inconclusive")
                    self.assertIn("Root cause unknown", report["summary"])
                else:
                    self.assertTrue(report["candidates"])
                    self.assertEqual(report["candidates"][0]["category"], category)
        evaluation = main.run_evaluation({"id": "test-user"})
        self.assertEqual(evaluation["top1_accuracy"], 100)

    def test_import_rejects_bad_timestamp_and_redacts_secrets(self):
        payload = b'{"records":[{"timestamp":"2026-10-28T10:00:00Z","service":"api","message":"Authorization: Bearer abc123","api_key":"private"},{"service":"api","message":"missing timestamp"}]}'
        records, errors, skipped = main.parse_import("sample.json", payload)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(skipped, 0)
        self.assertNotIn("abc123", records[0]["message"])
        self.assertEqual(records[0]["raw"]["api_key"], "[REDACTED]")

    def test_plain_text_log_parser_preserves_source_reference(self):
        payload = b"2026-10-28T10:30:00Z payment-service [ERROR] Database connection timeout\n"
        records, errors, _ = main.parse_import("payment.log", payload)
        self.assertFalse(errors)
        self.assertEqual(records[0]["service"], "payment-service")
        self.assertEqual(records[0]["source_reference"], "payment.log:1")

    def test_metric_anomaly_requires_baseline_or_enough_samples(self):
        record, error, _ = main.normalize_record(
            {"timestamp": "2026-10-28T10:30:00Z", "source_type": "metric",
             "service": "search-service", "metric": "cpu_percent",
             "value": 96, "baseline": 40}, "metrics.json:1")
        self.assertIsNone(error)
        anomalies, limitations = main.detect_metric_anomalies([{**record, "id": "EVD-1"}])
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["baseline"], 40)
        self.assertFalse(limitations)

        record.pop("metadata")
        record["metadata"] = {"metric": "cpu_percent", "value": 42}
        anomalies, limitations = main.detect_metric_anomalies([{**record, "id": f"EVD-{index}"} for index in range(3)])
        self.assertFalse(anomalies)
        self.assertTrue(limitations)


if __name__ == "__main__":
    unittest.main()
