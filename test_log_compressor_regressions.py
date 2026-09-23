import json
import unittest
from unittest.mock import patch

from utils.log_compressor import (
    COMPRESSION_VERSION,
    LogCompressor,
    LogCompressorConfig,
    estimate_log_tokens,
    generate_summary_statistics,
    identify_aggregate_dimension,
)


class LogCompressorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {
                "@timestamp": "2026-09-23T10:00:00Z",
                "source.ip": "10.0.0.1",
                "destination.ip": "10.0.0.2",
                "source.user.name": "support",
                "event.action": "login",
                "event.reason": "invalid_credentials",
                "fortinet.firewall.subtype": "system",
                "fortinet.firewall.status": "failed",
                "observer.name": "FW-A",
                "rule.id": "8",
                "rule.name": "Login policy",
            },
            {
                "@timestamp": "2026-09-23T10:01:00Z",
                "source.ip": "10.0.0.2",
                "destination.ip": "10.0.0.3",
                "source.user.name": "admin",
                "event.action": "delete",
                "event.reason": "account_removed",
                "fortinet.firewall.subtype": "config",
                "fortinet.firewall.status": "success",
                "observer.name": "FW-B",
                "rule.id": "9",
                "rule.name": "Admin policy",
            },
        ]

    def test_summary_reads_ecs_fields_without_unknown(self):
        summary = generate_summary_statistics(self.records)
        self.assertEqual(summary["src_ip_stats"], {"10.0.0.1": 1, "10.0.0.2": 1})
        self.assertEqual(summary["user_stats"], {"support": 1, "admin": 1})
        self.assertEqual(summary["reason_stats"], {"invalid_credentials": 1, "account_removed": 1})
        self.assertEqual(summary["device_stats"], {"FW-A": 1, "FW-B": 1})
        self.assertNotIn("unknown", json.dumps({
            "src_ip_stats": summary["src_ip_stats"],
            "user_stats": summary["user_stats"],
            "reason_stats": summary["reason_stats"],
            "device_stats": summary["device_stats"],
        }, ensure_ascii=False))

    def test_aggregate_uses_ecs_values_as_distinct_group_keys(self):
        compressor = LogCompressor()
        dimension, fields = "source_ip", ["source.ip"]
        groups = compressor._aggregate_logs(self.records, dimension, fields)
        self.assertEqual({g["_group_key"] for g in groups}, {"10.0.0.1", "10.0.0.2"})

    def test_field_compression_keeps_graph_and_ecs_fields(self):
        record = dict(self.records[0])
        record.update({f"noise_{i}": i for i in range(30)})
        config = LogCompressorConfig()
        config.field_threshold = 8
        compressor = LogCompressor(config)
        compressed = compressor._compress_fields(record)
        for field in (
            "source.ip", "destination.ip", "source.user.name", "event.action",
            "event.reason", "fortinet.firewall.subtype", "fortinet.firewall.status",
            "observer.name", "rule.id", "rule.name",
        ):
            self.assertIn(field, compressed)

    def test_bert_fallback_scores_are_not_uniform(self):
        compressor = LogCompressor()
        with patch.object(compressor, "_load_bert_model", return_value=(None, None)):
            scores = compressor._calculate_importance_scores(
                self.records + [{"message": "unrelated"}], "查询 support 登录失败"
            )
        self.assertGreater(len(set(scores)), 1)

    def test_compression_version_is_explicit(self):
        self.assertEqual(COMPRESSION_VERSION, "ecs-v2")

    def test_log_text_is_not_count_truncated_when_under_budget(self):
        config = LogCompressorConfig()
        config.max_output_tokens = 100000
        config.max_output_records = 3
        compressor = LogCompressor(config)
        logs = [{"source.ip": f"10.0.0.{i}", "message": f"event-{i}"} for i in range(1, 6)]
        text = compressor.compress(logs, question="查询日志", return_format="text")
        for i in range(1, 6):
            self.assertIn(f"event-{i}", text)

    def test_token_estimate_includes_summary_budget(self):
        logs = self.records * 5
        raw_only = estimate_log_tokens(logs, summary_text="")
        with_summary = estimate_log_tokens(logs)
        self.assertGreater(with_summary, raw_only)


if __name__ == "__main__":
    unittest.main()
