"""Regression tests for brute-force Top3 trace selection and language contracts.

These tests deliberately stay at the pure-function boundary.  They do not
start OpenSearch or the FastAPI stream; the integration path can therefore
reuse them in the lightweight development environment.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import patch


# Keep the tests runnable without the production-only LangChain/Pydantic
# dependencies, matching the compatibility shims in the existing regression
# suites.
try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic_stub = types.ModuleType("pydantic")
    pydantic_schema_stub = types.ModuleType("pydantic.schema")
    pydantic_stub.BaseModel = object
    pydantic_stub.Field = lambda default=None, **kwargs: default
    pydantic_schema_stub.model_schema = lambda *args, **kwargs: {}
    sys.modules["pydantic"] = pydantic_stub
    sys.modules["pydantic.schema"] = pydantic_schema_stub

# Other regression modules may have installed a smaller compatibility stub
# before test discovery reaches this file.  Fill only the attributes required
# by custom_template without replacing an existing real module.
if "pydantic.schema" not in sys.modules:
    try:
        import pydantic.schema  # noqa: F401
    except ImportError:
        pydantic_schema_stub = types.ModuleType("pydantic.schema")
        pydantic_schema_stub.model_schema = lambda *args, **kwargs: {}
        sys.modules["pydantic.schema"] = pydantic_schema_stub

try:
    import langchain  # noqa: F401
except ImportError:
    langchain_stub = types.ModuleType("langchain")
    agents_stub = types.ModuleType("langchain.agents")
    prompts_stub = types.ModuleType("langchain.prompts")
    schema_stub = types.ModuleType("langchain.schema")
    agents_stub.Tool = object
    agents_stub.AgentExecutor = object
    agents_stub.AgentOutputParser = object
    prompts_stub.StringPromptTemplate = object
    schema_stub.AgentAction = object
    schema_stub.AgentFinish = object
    sys.modules["langchain"] = langchain_stub
    sys.modules["langchain.agents"] = agents_stub
    sys.modules["langchain.prompts"] = prompts_stub
    sys.modules["langchain.schema"] = schema_stub

agents_stub = sys.modules.get("langchain.agents")
if agents_stub is not None:
    agents_stub.Tool = getattr(agents_stub, "Tool", object)
    agents_stub.AgentExecutor = getattr(agents_stub, "AgentExecutor", object)
    agents_stub.AgentOutputParser = getattr(agents_stub, "AgentOutputParser", object)
prompts_stub = sys.modules.get("langchain.prompts")
if prompts_stub is None:
    prompts_stub = types.ModuleType("langchain.prompts")
    sys.modules["langchain.prompts"] = prompts_stub
prompts_stub.StringPromptTemplate = getattr(prompts_stub, "StringPromptTemplate", object)
schema_stub = sys.modules.get("langchain.schema")
if schema_stub is not None:
    schema_stub.AgentAction = getattr(schema_stub, "AgentAction", object)
    schema_stub.AgentFinish = getattr(schema_stub, "AgentFinish", object)


from stream_formatter import contains_cjk, detect_response_language
from custom_template import compact_observation_for_llm
from tools.brute_force import (
    _auto_trace_brute_force_ips,
    _calculate_ip_priority,
    _is_brute_force_detection_hit,
)
from tools.ip_trace import build_graph_data


def _attack_record(ip: str, timestamp: str, *, subtype: str = "system", action: str = "login", status: str = "failed", reason: str = "invalid_credentials") -> dict:
    return {
        "@timestamp": timestamp,
        "attack_src": ip,
        "source.ip": ip,
        "event.action": action,
        "event.reason": reason,
        "fortinet.firewall.subtype": subtype,
        "fortinet.firewall.status": status,
        "message": "Login failed",
    }


class BruteForceTop3ContractTests(unittest.TestCase):
    def test_priority_uses_complete_ip_stats_and_stops_at_three(self):
        """Ranking must not be inferred from the compressed data sample."""
        result = {
            # This intentionally misleading sample has a different order.
            "data": [_attack_record("10.0.0.99", "2026-03-26 00:00:00")],
            "ip_stats": [
                {"ip": "10.0.0.1", "count": 10, "percentage": 47.62},
                {"ip": "10.0.0.2", "count": 5, "percentage": 23.81},
                {"ip": "10.0.0.3", "count": 3, "percentage": 14.29},
                {"ip": "10.0.0.4", "count": 2, "percentage": 9.52},
                {"ip": "10.0.0.5", "count": 1, "percentage": 4.76},
            ],
        }
        self.assertEqual(
            _calculate_ip_priority(result),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

    def test_priority_returns_one_when_first_ip_reaches_eighty_percent(self):
        result = {
            "data": [],
            "ip_stats": [
                {"ip": "10.0.0.1", "count": 9, "percentage": 90.0},
                {"ip": "10.0.0.2", "count": 1, "percentage": 10.0},
            ],
        }
        self.assertEqual(_calculate_ip_priority(result), ["10.0.0.1"])

    def test_model_summary_uses_selected_trace_ips_when_coverage_stops_early(self):
        compacted = compact_observation_for_llm(json.dumps({
            "count": 10,
            "ip_stats": [
                {"ip": "10.0.0.1", "count": 9, "percentage": 90.0},
                {"ip": "10.0.0.2", "count": 1, "percentage": 10.0},
            ],
            "trace_info": {
                "trace_ips": ["10.0.0.1"],
                "trace_ip_stats": [
                    {"ip": "10.0.0.1", "count": 9, "percentage": 90.0}
                ],
                "ip_details": [],
            },
            "data": [
                _attack_record("10.0.0.1", "2026-03-26 10:00:00"),
                _attack_record("10.0.0.2", "2026-03-26 11:00:00"),
            ],
        }, ensure_ascii=False))
        summary = json.loads(compacted)["ip_summary"]
        self.assertEqual(summary["selected_trace_ips"], ["10.0.0.1"])
        self.assertEqual([item["ip"] for item in summary["top3"]], ["10.0.0.1"])

    def test_model_summary_keeps_real_records_for_every_selected_ip(self):
        records = [
            _attack_record("10.0.0.1", f"2026-03-26 10:{minute:02d}:00")
            for minute in range(40)
        ]
        records.extend(
            _attack_record("10.0.0.2", f"2026-03-26 11:{minute:02d}:00")
            for minute in range(30)
        )
        records.extend(
            _attack_record("10.0.0.3", f"2026-03-26 12:{minute:02d}:00")
            for minute in range(20)
        )
        compacted = json.loads(compact_observation_for_llm(json.dumps({
            "count": 90,
            "ip_stats": [
                {"ip": "10.0.0.1", "count": 40, "percentage": 44.4},
                {"ip": "10.0.0.2", "count": 30, "percentage": 33.3},
                {"ip": "10.0.0.3", "count": 20, "percentage": 22.2},
            ],
            "trace_info": {
                "trace_ips": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                "trace_ip_stats": [
                    {"ip": "10.0.0.1", "count": 40, "percentage": 44.4},
                    {"ip": "10.0.0.2", "count": 30, "percentage": 33.3},
                    {"ip": "10.0.0.3", "count": 20, "percentage": 22.2},
                ],
            },
            "data": records,
        }, ensure_ascii=False)))

        sampled_ips = {_attack["attack_src"] for _attack in compacted["top_ip_records"]}
        self.assertEqual(sampled_ips, {"10.0.0.1", "10.0.0.2", "10.0.0.3"})

    def test_large_trace_payload_cannot_hide_selected_ip_events(self):
        """Trace activities must not consume the Top-IP evidence budget."""
        selected_ips = ["10.180.40.80", "10.180.30.70", "10.180.95.33"]
        records = []
        for rank, ip in enumerate(selected_ips, 1):
            records.extend(
                _attack_record(ip, f"2026-03-26 {rank + 2:02d}:0{minute}:00")
                | {
                    "source.user.name": f"user_{rank}_{minute}",
                    "observer.name": "GuZ_OFFICE_500E",
                }
                for minute in range(5)
            )

        large_activities = json.dumps({
            "steps": [
                {"step": index, "title": "trace", "detail": "x" * 800}
                for index in range(1, 6)
            ],
            "ppl_query": "q" * 3000,
            "data": records,
        })
        observation = {
            "count": 250,
            "ip_stats": [
                {"ip": ip, "count": 5, "percentage": 2.0}
                for ip in selected_ips
            ],
            "trace_info": {
                "trace_ips": selected_ips,
                "trace_ip_stats": [
                    {"ip": ip, "count": 5, "percentage": 2.0}
                    for ip in selected_ips
                ],
                "ip_details": [
                    {
                        "ip": ip,
                        "rank": rank,
                        "brute_force_count": 5,
                        "trace_event_count": 20,
                        "time_window": "2026-03-26T00:00:00+08:00 ~ 2026-03-26T01:00:00+08:00",
                        "activities": large_activities,
                        "graph_data": {"render_lines": [{"payload": "y" * 500}] * 20},
                    }
                    for rank, ip in enumerate(selected_ips, 1)
                ],
            },
            "data": records,
            "compression": {
                "compressed": True,
                "original_count": 250,
                "compressed_count": 10,
                "summary_text": "summary " * 250,
            },
        }

        compacted = json.loads(
            compact_observation_for_llm(json.dumps(observation, ensure_ascii=False))
        )
        self.assertNotIn("activities", json.dumps(compacted, ensure_ascii=False))
        self.assertNotIn("graph_data", compacted.get("trace_info", {}))
        details = compacted["top_ip_details"]
        self.assertEqual([item["ip"] for item in details], selected_ips)
        self.assertTrue(all(item["records_complete"] for item in details))
        records_by_ip = {
            ip: [item for item in compacted["top_ip_records"] if item["ip"] == ip]
            for ip in selected_ips
        }
        self.assertEqual({ip: len(items) for ip, items in records_by_ip.items()}, {
            ip: 5 for ip in selected_ips
        })

    def test_every_summary_event_matches_same_ip_detection_line(self):
        selected_ips = ["10.180.40.80", "10.180.30.70", "10.180.95.33"]
        records = [
            _attack_record("10.180.40.80", "2026-03-26 03:07:12", reason="wrong_password")
            | {"source.user.name": "admin", "observer.name": "GuZ_OFFICE_500E"},
            _attack_record("10.180.40.80", "2026-03-26 18:40:19", reason="bad_auth_request")
            | {"source.user.name": "backup_user", "observer.name": "GuZ_OFFICE_500E"},
            _attack_record("10.180.30.70", "2026-03-26 08:15:21", reason="invalid_credentials")
            | {"source.user.name": "root", "observer.name": "GuZ_BRANCH_100"},
            _attack_record("10.180.95.33", "2026-03-26 13:17:45", reason="invalid_credentials")
            | {"source.user.name": "admin", "observer.name": "GuZ_OFFICE_500E"},
            _attack_record("10.180.95.33", "2026-03-26 18:28:48", reason="wrong_password")
            | {"source.user.name": "sysadmin", "observer.name": "GuZ_OFFICE_500E"},
        ]
        observation = json.loads(compact_observation_for_llm(json.dumps({
            "count": len(records),
            "ip_stats": [
                {"ip": "10.180.40.80", "count": 2, "percentage": 40.0},
                {"ip": "10.180.30.70", "count": 1, "percentage": 20.0},
                {"ip": "10.180.95.33", "count": 2, "percentage": 40.0},
            ],
            "trace_info": {
                "trace_ips": selected_ips,
                "trace_ip_stats": [
                    {"ip": "10.180.40.80", "count": 2, "percentage": 40.0},
                    {"ip": "10.180.30.70", "count": 1, "percentage": 20.0},
                    {"ip": "10.180.95.33", "count": 2, "percentage": 40.0},
                ],
            },
            "data": records,
        }, ensure_ascii=False)))

        for ip in selected_ips:
            ip_records = [record for record in records if record["attack_src"] == ip]
            graph = build_graph_data({"data": ip_records})
            global_lines = [
                line for line in graph["render_lines"]
                if line.get("event_role") == "global_hit"
            ]
            summary_events = [
                event for event in observation["top_ip_records"]
                if event.get("ip") == ip
            ]
            self.assertEqual(len(summary_events), len(ip_records))
            self.assertEqual(
                sum(int(line.get("count", 0)) for line in global_lines),
                len(ip_records),
            )
            for event in summary_events:
                event_user = event.get("source.user.name")
                event_time = event.get("@timestamp")
                event_reason = event.get("event.reason")
                matching_lines = []
                for line in global_lines:
                    steps = line.get("steps", [])
                    attacker = next(
                        (step.get("name") for step in steps if step.get("type") == "attacker"),
                        None,
                    )
                    user = next(
                        (step.get("name") for step in steps if step.get("type") == "user"),
                        None,
                    )
                    if (
                        attacker == ip
                        and user == event_user
                        and line.get("first_seen") <= event_time <= line.get("last_seen")
                        and line.get("details", {}).get("event_reason") == event_reason
                    ):
                        matching_lines.append(line)
                self.assertTrue(matching_lines, event)

    @patch("tools.brute_force.ip_trace_request")
    def test_trace_calls_match_top3_order_and_independent_windows(self, trace_request):
        trace_request.side_effect = lambda ip, start_time, end_time, gid: {
            "trace_info": {
                "ip": ip,
                "status": "success",
                "time_window": f"{start_time} ~ {end_time}",
                "graph_data": {"render_lines": []},
            }
        }
        result = _auto_trace_brute_force_ips(
            {
                "data": [
                    _attack_record("10.0.0.1", "2026-03-26 10:00:00"),
                    _attack_record("10.0.0.1", "2026-03-26 11:00:00"),
                    _attack_record("10.0.0.2", "2026-03-26 12:00:00"),
                    _attack_record("10.0.0.2", "2026-03-26 13:00:00"),
                    _attack_record("10.0.0.3", "2026-03-26 14:00:00"),
                    _attack_record("10.0.0.3", "2026-03-26 15:00:00"),
                    # The fourth IP is deliberately present and must not trace.
                    _attack_record("10.0.0.4", "2026-03-26 16:00:00"),
                ],
                "ip_stats": [
                    {"ip": "10.0.0.1", "count": 10},
                    {"ip": "10.0.0.2", "count": 5},
                    {"ip": "10.0.0.3", "count": 3},
                    {"ip": "10.0.0.4", "count": 2},
                ],
            },
            start_time="2026-03-26 00:00:00",
            end_time="2026-03-26 23:59:59",
            gid="19936",
        )

        self.assertEqual(trace_request.call_count, 3)
        self.assertEqual(
            [call.kwargs["ip"] for call in trace_request.call_args_list],
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )
        windows = {
            call.kwargs["ip"]: (call.kwargs["start_time"], call.kwargs["end_time"])
            for call in trace_request.call_args_list
        }
        self.assertEqual(
            windows["10.0.0.1"],
            ("2026-03-26T09:30:00+08:00", "2026-03-26T11:30:00+08:00"),
        )
        self.assertEqual(
            windows["10.0.0.2"],
            ("2026-03-26T11:30:00+08:00", "2026-03-26T13:30:00+08:00"),
        )
        self.assertEqual(
            windows["10.0.0.3"],
            ("2026-03-26T13:30:00+08:00", "2026-03-26T15:30:00+08:00"),
        )
        self.assertEqual(
            [detail.get("ip") for detail in result.get("ip_details", [])],
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )
        self.assertEqual(
            result.get("trace_ips"),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )
        self.assertEqual(
            [item["ip"] for item in result.get("trace_ip_stats", [])],
            result["trace_ips"],
        )

        # The graph metadata is the machine-readable counterpart of the
        # report Top3.  It must retain rank/count/window for every selected IP.
        for rank, detail in enumerate(result["ip_details"], 1):
            self.assertEqual(detail["rank"], rank)
            self.assertEqual(detail["brute_force_count"], {1: 10, 2: 5, 3: 3}[rank])
            self.assertEqual(detail["trace_event_count"], len(detail["graph_data"]["render_lines"]))
            self.assertEqual(detail["time_window"], f"{windows[detail['ip']][0]} ~ {windows[detail['ip']][1]}")
            graph = detail["graph_data"]
            self.assertEqual(graph["ip"], detail["ip"])
            self.assertEqual(graph["rank"], rank)
            self.assertEqual(graph["brute_force_count"], detail["brute_force_count"])
            self.assertEqual(graph["trace_event_count"], detail["trace_event_count"])
            self.assertEqual(graph["time_window"], detail["time_window"])
            for line in graph["render_lines"]:
                self.assertEqual(line.get("event_role"), "global_hit")

    def test_detection_hit_classifier_matches_the_brute_force_ppl(self):
        self.assertTrue(_is_brute_force_detection_hit(_attack_record("10.0.0.1", "2026-03-26 10:00:00")))
        self.assertTrue(
            _is_brute_force_detection_hit(
                _attack_record(
                    "10.0.0.1",
                    "2026-03-26 10:00:00",
                    subtype="vpn",
                    action="",
                    status="",
                )
                | {"message": "SSL user failed to logged in"}
            )
        )
        self.assertFalse(
            _is_brute_force_detection_hit(
                _attack_record("10.0.0.1", "2026-03-26 10:00:00", reason="ip_blocked")
            )
        )
        self.assertFalse(
            _is_brute_force_detection_hit(
                _attack_record(
                    "10.0.0.1",
                    "2026-03-26 10:00:00",
                    subtype="ips",
                    action="log_only",
                    status="blocked",
                )
            )
        )


class ResponseLanguageContractTests(unittest.TestCase):
    def test_language_is_detected_once_from_original_user_input(self):
        self.assertEqual(
            detect_response_language("2026年gid19936的3月26日有哪些暴力破解记录"),
            "zh",
        )
        self.assertEqual(
            detect_response_language(
                "What are the brute force attack records for gid 19936 on March 26, 2026?"
            ),
            "en",
        )

    def test_english_fixed_status_strings_contain_no_cjk(self):
        english_status = (
            "Starting tool execution...\n"
            "Step 5: Query complete, total 250 records.\n"
            "Final Answer:"
        )
        self.assertFalse(contains_cjk(english_status))

    def test_chinese_request_can_contain_technical_english_without_switching_language(self):
        request = "查询 gid19936 的 brute_force_request 记录"
        self.assertEqual(detect_response_language(request), "zh")


if __name__ == "__main__":
    unittest.main()
