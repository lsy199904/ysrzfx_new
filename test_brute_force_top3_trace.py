import sys
import types
import unittest
from unittest.mock import patch

# Keep these focused tests runnable in the lightweight local interpreter used
# for pure graph/priority regression checks.
try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic_stub = types.ModuleType("pydantic")
    pydantic_stub.BaseModel = object
    pydantic_stub.Field = lambda default=None, **kwargs: default
    sys.modules["pydantic"] = pydantic_stub

try:
    import langchain  # noqa: F401
except ImportError:
    langchain_stub = types.ModuleType("langchain")
    agents_stub = types.ModuleType("langchain.agents")
    schema_stub = types.ModuleType("langchain.schema")
    agents_stub.Tool = object
    agents_stub.AgentExecutor = object
    schema_stub.AgentFinish = object
    sys.modules["langchain"] = langchain_stub
    sys.modules["langchain.agents"] = agents_stub
    sys.modules["langchain.schema"] = schema_stub

from tools.brute_force import (
    MAX_TRACE_IPS,
    _auto_trace_brute_force_ips,
    _calculate_ip_priority,
)
from tools.ip_trace import build_graph_data


class BruteForceTop3TraceTests(unittest.TestCase):
    def test_priority_keeps_80_percent_rule_and_caps_at_three(self):
        self.assertEqual(MAX_TRACE_IPS, 3)
        self.assertEqual(
            _calculate_ip_priority({
                "ip_stats": [
                    {"ip": "10.0.0.1", "count": 8},
                    {"ip": "10.0.0.2", "count": 2},
                    {"ip": "10.0.0.3", "count": 1},
                ],
                "data": [],
            }),
            ["10.0.0.1", "10.0.0.2"],
        )
        self.assertEqual(
            _calculate_ip_priority({
                "ip_stats": [
                    {"ip": "10.0.0.1", "count": 1},
                    {"ip": "10.0.0.2", "count": 1},
                    {"ip": "10.0.0.3", "count": 1},
                    {"ip": "10.0.0.4", "count": 1},
                ],
                "data": [],
            }),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

    @patch("tools.brute_force.ip_trace_request")
    def test_auto_trace_calls_only_selected_top3_and_adds_metadata(self, trace_request):
        def fake_trace(ip, start_time, end_time, gid):
            return {
                "trace_info": {
                    "ip": ip,
                    "status": "success",
                    "time_window": f"{start_time} ~ {end_time}",
                    "graph_data": {
                        "render_lines": [
                            {"line_id": f"{ip}-line", "count": 2, "event_role": "trace_context"}
                        ],
                        "stats": {"event_count": 2},
                    },
                }
            }

        trace_request.side_effect = fake_trace
        records = []
        for ip, times in (
            ("10.0.0.1", ("2026-03-26 10:00:00", "2026-03-26 10:05:00")),
            ("10.0.0.2", ("2026-03-26 11:00:00", "2026-03-26 11:05:00")),
            ("10.0.0.3", ("2026-03-26 12:00:00", "2026-03-26 12:05:00")),
            ("10.0.0.4", ("2026-03-26 13:00:00", "2026-03-26 13:05:00")),
        ):
            records.extend({"attack_src": ip, "@timestamp": value} for value in times)

        result = _auto_trace_brute_force_ips(
            {
                "data": records,
                "ip_stats": [
                    {"ip": "10.0.0.1", "count": 2},
                    {"ip": "10.0.0.2", "count": 2},
                    {"ip": "10.0.0.3", "count": 2},
                    {"ip": "10.0.0.4", "count": 2},
                ],
            },
            start_time="2026-03-26 00:00:00",
            end_time="2026-03-26 23:59:59",
            gid="19936",
        )

        self.assertEqual(trace_request.call_count, 3)
        self.assertEqual(result["trace_ips"], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        details = result["ip_details"]
        self.assertEqual([item["ip"] for item in details], result["trace_ips"])
        self.assertEqual([item["rank"] for item in details], [1, 2, 3])
        self.assertEqual([item["brute_force_count"] for item in details], [2, 2, 2])
        self.assertTrue(all(item["trace_event_count"] == 2 for item in details))
        self.assertTrue(all(item["graph_data"]["ip"] == item["ip"] for item in details))
        self.assertTrue(all(item["graph_data"]["rank"] == item["rank"] for item in details))
        self.assertNotIn("10.0.0.4", [call.kwargs["ip"] for call in trace_request.call_args_list])

    def test_render_lines_mark_detection_and_context_without_dropping_context(self):
        graph = build_graph_data({
            "data": [
                {
                    "@timestamp": "2026-03-26 10:00:00",
                    "source.ip": "10.0.0.1",
                    "source.user.name": "support",
                    "event.action": "login",
                    "fortinet.firewall.subtype": "system",
                    "fortinet.firewall.status": "failed",
                    "event.reason": "invalid_credentials",
                },
                {
                    "@timestamp": "2026-03-26 10:01:00",
                    "source.ip": "10.0.0.1",
                    "destination.ip": "10.0.0.2",
                    "event.action": "accept",
                    "fortinet.firewall.subtype": "forward",
                    "fortinet.firewall.status": "success",
                },
                {
                    "@timestamp": "2026-03-26 10:02:00",
                    "source.ip": "10.0.0.1",
                    "source.user.name": "support",
                    "event.action": "login",
                    "fortinet.firewall.subtype": "system",
                    "fortinet.firewall.status": "failed",
                    "event.reason": "ip_blocked",
                },
            ]
        })

        lines = graph["render_lines"]
        self.assertEqual(len(lines), 3)
        self.assertEqual(
            {line["event_role"] for line in lines},
            {"detection_hit", "trace_context"},
        )
        self.assertEqual(
            sum(line["count"] for line in lines if line["event_role"] == "detection_hit"),
            1,
        )
        self.assertEqual(sum(line["count"] for line in lines), 3)


if __name__ == "__main__":
    unittest.main()
