import json
import sys
import types
import unittest
from unittest.mock import patch

# The production environment installs these dependencies. Lightweight fallbacks
# keep the pure unit tests runnable in a minimal development interpreter.
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
    _auto_trace_brute_force_ips,
    _get_ip_attack_time_range,
    _get_ip_first_attack_time,
    _normalize_attack_time,
)
from tools.account_security_monitor import _auto_trace_account_security_ips
from tools.network_attack_detection import _auto_trace_network_attack_ips
from tools.ip_trace import build_trace_window_range, compact_graph_data
from tools.ip_trace import IP_TRACE_PPL_TEMPLATE, _build_trace_result, build_graph_data


class GraphDataRegressionTests(unittest.TestCase):
    def test_local_timestamp_is_not_shifted_twice(self):
        self.assertEqual(
            _normalize_attack_time("2026-03-26 19:03:21"),
            "2026-03-26 19:03:21",
        )

    def test_explicit_utc_timestamp_is_converted_once(self):
        self.assertEqual(
            _normalize_attack_time("2026-03-26T11:03:21Z"),
            "2026-03-26 19:03:21",
        )

    def test_ip_first_attack_time_uses_local_query_result(self):
        result = {
            "data": [
                {
                    "@timestamp": "2026-03-26 19:03:21",
                    "attack_src": "10.180.120.160",
                }
            ]
        }
        self.assertEqual(
            _get_ip_first_attack_time(result, "10.180.120.160"),
            "2026-03-26 19:03:21",
        )

    def test_ip_trace_window_covers_earliest_and_latest_attack(self):
        result = {
            "data": [
                {"attack_src": "10.180.120.160", "@timestamp": "2026-03-26 10:35:12"},
                {"attack_src": "10.180.120.160", "@timestamp": "2026-03-26 11:03:21"},
                {"attack_src": "10.180.120.160", "@timestamp": "2026-03-26 11:40:00"},
            ]
        }
        first, last = _get_ip_attack_time_range(result, "10.180.120.160")
        self.assertEqual(first, "2026-03-26 10:35:12")
        self.assertEqual(last, "2026-03-26 11:40:00")
        self.assertEqual(
            build_trace_window_range(first, last, pre_minutes=30, post_minutes=30),
            {
                "start_time": "2026-03-26 10:05:12",
                "end_time": "2026-03-26 12:10:00",
            },
        )

    @patch("tools.brute_force.ip_trace_request")
    def test_brute_force_auto_trace_uses_full_ip_range(self, trace_request):
        trace_request.return_value = {
            "trace_info": {
                "status": "success",
                "time_window": "2026-03-26 00:00:00 ~ 2026-03-26 23:59:59",
            }
        }
        result = _auto_trace_brute_force_ips(
            {
                "data": [
                    {"attack_src": "10.180.120.160", "@timestamp": "2026-03-26 10:35:12"},
                    {"attack_src": "10.180.120.160", "@timestamp": "2026-03-26 11:40:00"},
                ]
            },
            start_time="2026-03-26 00:00:00",
            end_time="2026-03-26 23:59:59",
            gid=None,
        )
        self.assertEqual(result["status"], "success")
        trace_request.assert_called_once_with(
            ip="10.180.120.160",
            start_time="2026-03-26 00:00:00",
            end_time="2026-03-26 23:59:59",
            gid=None,
        )

    def test_trace_query_uses_only_persisted_ip_fields(self):
        self.assertNotIn("remip", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("eval attack_src", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("attack_src", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("source.ip", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("destination.ip", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("fortinet.firewall.status", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("rule.id", IP_TRACE_PPL_TEMPLATE)

    def test_trace_http_error_is_not_reported_as_success(self):
        raw_result = json.dumps(
            {
                "http_status": 400,
                "error": "Field [remip] not found.",
                "data": [],
            }
        )
        result = _build_trace_result(
            raw_result,
            "10.180.120.160",
            "2026-03-26 18:33:21",
            "2026-03-26 19:03:21",
        )
        self.assertEqual(result["trace_info"]["status"], "error")
        self.assertEqual(result["trace_info"]["graph_data"], {})

    def test_successful_trace_builds_graph_with_observer_device(self):
        raw_result = json.dumps(
            {
                "http_status": 200,
                "error": "",
                "data": [
                    {
                        "@timestamp": "2026-03-26 19:03:21",
                        "source.ip": "10.180.120.160",
                        "destination.ip": "10.180.3.147",
                        "source.user.name": "support",
                        "observer.name": "GuZ_OFFICE_500E",
                        "event.action": "login",
                        "event.reason": "invalid_credentials",
                        "message": "Login failed for user support",
                        "fortinet.firewall.subtype": "system",
                    }
                ],
            }
        )
        result = _build_trace_result(
            raw_result,
            "10.180.120.160",
            "2026-03-26 18:33:21",
            "2026-03-26 19:03:21",
        )
        graph = result["trace_info"]["graph_data"]
        self.assertEqual(result["trace_info"]["status"], "success")
        self.assertNotIn("nodes", graph)
        self.assertNotIn("edges", graph)
        self.assertEqual(set(graph), {"render_lines", "stats"})
        self.assertEqual(graph["stats"]["event_count"], 1)

    def test_current_field_mapping_restores_graph_chain_nodes(self):
        records = [
            {
                "@timestamp": "2026-03-26 11:03:21",
                "source.ip": "10.180.120.160",
                "destination.ip": "10.180.3.147",
                "source.user.name": "li_si",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "delete",
                "fortinet.firewall.subtype": "config",
                "fortinet.firewall.status": "success",
                "message": "Local user li_si has been deleted",
                "rule.id": "8.0",
                "rule.name": "Policy 8.0",
            },
            {
                "@timestamp": "2026-03-26 11:03:22",
                "source.ip": "10.180.120.160",
                "destination.ip": "10.180.3.147",
                "source.user.name": "support",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "login",
                "fortinet.firewall.subtype": "system",
                "fortinet.firewall.status": "failed",
                "message": "Login failed for user support",
            },
        ]
        graph = build_graph_data({"data": records})
        node_types = {node["type"] for node in graph["nodes"]}
        self.assertTrue({"attacker", "host", "user", "oss", "action", "subtype"} <= node_types)
        self.assertIn("8.0", {node["id"] for node in graph["nodes"]})
        relations = {edge["relation"] for edge in graph["edges"]}
        self.assertTrue({"uses_account", "performs_action", "has_subtype"} <= relations)

    def test_graph_matches_legacy_two_lane_layout_and_preserves_status(self):
        records = [
            {
                "@timestamp": "2026-03-26 11:03:21",
                "attack_src": "10.180.120.160",
                "source.ip": "10.180.120.160",
                "destination.ip": "10.180.3.147",
                "source.user.name": "li_si",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "delete",
                "fortinet.firewall.subtype": "config",
                "fortinet.firewall.status": "success",
                "message": "Local user li_si has been deleted",
                "rule.id": "8.0",
                "rule.name": "Policy 8.0",
            },
            {
                "@timestamp": "2026-03-26 11:03:21",
                "attack_src": "10.180.120.160",
                "source.ip": "10.180.120.160",
                "destination.ip": "10.180.3.147",
                "source.user.name": "support",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "login",
                "fortinet.firewall.subtype": "system",
                "fortinet.firewall.status": "failed",
                "message": "Login failed for user support",
                "rule.id": "8.0",
                "rule.name": "Policy 8.0",
            },
            {
                "@timestamp": "2026-03-26 11:03:22",
                "attack_src": "10.180.120.160",
                "source.ip": "10.180.120.160",
                "destination.ip": "10.180.3.147",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "log_only",
                "fortinet.firewall.subtype": "ips",
                "fortinet.firewall.status": "blocked",
                "message": "IPS attack blocked",
                "rule.id": "8.0",
                "rule.name": "Policy 8.0",
            },
        ]

        graph = build_graph_data({"data": records})
        nodes = {node["id"]: node for node in graph["nodes"]}
        edges = {
            (edge["source"], edge["target"], edge["relation"]): edge
            for edge in graph["edges"]
        }

        self.assertEqual(nodes["user_li_si"]["status"], "success")
        self.assertEqual(nodes["action_delete"]["status"], "success")
        self.assertEqual(nodes["subtype_config"]["status"], "success")
        self.assertEqual(nodes["user_support"]["status"], "failed")
        self.assertEqual(nodes["action_login"]["status"], "failed")
        self.assertEqual(nodes["subtype_system"]["status"], "failed")
        self.assertEqual(nodes["10.180.3.147"]["status"], "blocked")
        self.assertEqual(nodes["action_log_only"]["status"], "blocked")
        self.assertEqual(nodes["subtype_ips"]["status"], "blocked")
        self.assertEqual(nodes["8.0"]["status"], "blocked")

        self.assertIn(("user_li_si", "action_delete", "performs_action"), edges)
        self.assertIn(("action_delete", "subtype_config", "has_subtype"), edges)
        self.assertIn(("subtype_config", "device_GuZ_OFFICE_500E", "targets_device"), edges)
        self.assertIn(("10.180.3.147", "action_log_only", "responds_with"), edges)
        self.assertIn(("action_log_only", "8.0", "matched_policy"), edges)
        self.assertEqual(edges[("action_delete", "subtype_config", "has_subtype")]["edge_status"], "success")
        self.assertEqual(edges[("10.180.3.147", "action_log_only", "responds_with")]["edge_status"], "blocked")
        self.assertEqual(edges[("action_log_only", "8.0", "matched_policy")]["edge_status"], "blocked")

        self.assertFalse(
            any(edge["relation"] == "operates_on" for edge in graph["edges"]),
        )
        self.assertEqual(
            len(graph["edges"]),
            len(edges),
            "edges should not contain duplicate source/target/relation entries",
        )

    def test_graph_reads_pipeline_renamed_top_level_status(self):
        graph = build_graph_data({
            "data": [{
                "@timestamp": "2026-09-15 20:22:00",
                "attack_src": "10.180.26.6",
                "source.ip": "10.180.26.6",
                "source.user.name": "support",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "login",
                "status": "failed",
                "fortinet.firewall.subtype": "system",
                "message": "Login failed for user support",
            }]
        })
        nodes = {node["id"]: node for node in graph["nodes"]}
        self.assertEqual(nodes["user_support"]["status"], "failed")
        self.assertEqual(nodes["action_login"]["status"], "failed")
        self.assertEqual(nodes["subtype_system"]["status"], "failed")

    def test_render_lines_adds_ordered_upper_and_lower_paths(self):
        graph = build_graph_data({
            "data": [
                {
                    "@timestamp": "2026-03-26 10:35:12",
                    "source.ip": "10.180.120.160",
                    "source.user.name": "li_si",
                    "observer.name": "GuZ_OFFICE_500E",
                    "event.action": "Delete",
                    "fortinet.firewall.subtype": "config",
                    "fortinet.firewall.status": "success",
                },
                {
                    "@timestamp": "2026-03-26 11:03:21",
                    "source.ip": "10.180.120.160",
                    "source.user.name": "support",
                    "observer.name": "GuZ_OFFICE_500E",
                    "event.action": "login",
                    "fortinet.firewall.subtype": "system",
                    "fortinet.firewall.status": "failed",
                },
                {
                    "@timestamp": "2026-03-26 11:03:22",
                    "source.ip": "10.180.120.160",
                    "destination.ip": "10.180.3.147",
                    "destination.port": 443,
                    "observer.name": "GuZ_OFFICE_500E",
                    "event.action": "accept",
                    "fortinet.firewall.subtype": "log_only",
                    "rule.id": "8.0",
                    "rule.name": "Policy 8.0",
                },
            ]
        })

        self.assertIn("render_lines", graph)
        self.assertEqual(len(graph["render_lines"]), 3)
        upper = [line for line in graph["render_lines"] if line["direction"] == "upper"]
        lower = [line for line in graph["render_lines"] if line["direction"] == "lower"]
        self.assertEqual(len(upper), 2)
        self.assertEqual(len(lower), 1)
        self.assertEqual(upper[0]["steps"][0], {"type": "attacker", "name": "10.180.120.160"})
        self.assertEqual(lower[0]["status"], "pass")
        self.assertIn("lower-10-180-120-160-10-180-3-147-traffic-log-only-443-8-0-pass", lower[0]["line_id"])
        self.assertEqual(lower[0]["steps"][2], {"type": "action", "name": "traffic"})
        self.assertEqual(lower[0]["details"]["destination_ip"], "10.180.3.147")
        self.assertEqual(lower[0]["details"]["destination_port"], 443)
        self.assertEqual(lower[0]["details"]["rule_id"], "8.0")
        self.assertEqual(lower[0]["details"]["rule_name"], "Policy 8.0")
        self.assertEqual(lower[0]["steps"][-1], {"type": "policy", "name": "Policy 8.0"})

    def test_traffic_graph_connects_subtype_to_oss_and_derives_accept_status(self):
        records = [
            {
                "@timestamp": "2026-09-15 20:21:56",
                "attack_src": "10.180.26.6",
                "source.ip": "10.180.26.6",
                "destination.ip": "10.180.158.209",
                "observer.name": "DS_KXCFG_100F",
                "event.action": "accept",
                "fortinet.firewall.subtype": "forward",
                "rule.id": "24",
                "rule.name": "FROM_TCP_CHD_Luke",
            }
        ]

        graph = build_graph_data({"data": records})
        nodes = {node["id"]: node for node in graph["nodes"]}
        edges = {
            (edge["source"], edge["target"], edge["relation"]): edge
            for edge in graph["edges"]
        }

        self.assertEqual(nodes["10.180.158.209"]["status"], "success")
        self.assertEqual(nodes["action_accept"]["status"], "success")
        self.assertEqual(nodes["24"]["status"], "success")
        self.assertIn(
            ("subtype_forward", "device_DS_KXCFG_100F", "targets_device"),
            edges,
        )
        self.assertEqual(
            edges[("10.180.158.209", "action_accept", "responds_with")]["edge_status"],
            "success",
        )
        self.assertEqual(
            edges[("subtype_forward", "device_DS_KXCFG_100F", "targets_device")]["edge_status"],
            "success",
        )

    def test_login_failure_message_propagates_to_action_and_edge_without_status_field(self):
        graph = build_graph_data({
            "data": [{
                "@timestamp": "2026-09-15 20:22:00",
                "attack_src": "10.180.26.6",
                "source.ip": "10.180.26.6",
                "destination.ip": "10.180.3.147",
                "source.user.name": "zhou_hui",
                "observer.name": "GuZ_OFFICE_500E",
                "event.action": "login",
                "event.reason": "invalid_credentials",
                "message": "Login failed for user zhou_hui",
                "fortinet.firewall.subtype": "system",
            }]
        })
        nodes = {node["id"]: node for node in graph["nodes"]}
        edges = {
            (edge["source"], edge["target"], edge["relation"]): edge
            for edge in graph["edges"]
        }

        self.assertEqual(nodes["user_zhou_hui"]["status"], "failed")
        self.assertEqual(nodes["action_login"]["status"], "failed")
        self.assertEqual(nodes["subtype_system"]["status"], "failed")
        self.assertEqual(
            edges[("user_zhou_hui", "action_login", "performs_action")]["edge_status"],
            "failed",
        )

    def test_compact_graph_data_exposes_only_render_lines_and_stats(self):
        compacted = compact_graph_data({
            "nodes": [{"id": "n1"}],
            "edges": [{"source": "n1", "target": "n2"}],
            "render_lines": [
                {"line_id": "upper-a", "direction": "upper", "count": 2},
                {"line_id": "lower-b", "direction": "lower", "count": 1},
            ],
            "stats": {"node_count": 1, "edge_count": 1},
        })
        self.assertEqual(set(compacted), {"render_lines", "stats"})
        self.assertEqual(compacted["stats"], {
            "event_count": 3,
            "line_count": 2,
            "upper_line_count": 1,
            "lower_line_count": 1,
        })

    def test_render_line_aggregation_keeps_status_port_and_target_distinct(self):
        records = []
        for status, port, target, timestamp in (
            ("success", 443, "10.0.0.1", "2026-03-26 10:00:00"),
            ("success", 443, "10.0.0.1", "2026-03-26 10:01:00"),
            ("failed", 443, "10.0.0.1", "2026-03-26 10:02:00"),
            ("success", 22, "10.0.0.1", "2026-03-26 10:03:00"),
            ("success", 443, "10.0.0.2", "2026-03-26 10:04:00"),
        ):
            records.append({
                "@timestamp": timestamp,
                "attack_src": "10.0.0.9",
                "destination.ip": target,
                "destination.port": port,
                "event.action": "accept",
                "fortinet.firewall.subtype": "forward",
                "fortinet.firewall.status": status,
                "observer.name": "fw-1",
                "rule.id": "8",
                "rule.name": "Policy 8",
            })
        graph = build_graph_data({"data": records})
        lines = graph["render_lines"]
        self.assertEqual(len(lines), 4)
        self.assertEqual(sorted(line["count"] for line in lines), [1, 1, 1, 2])
        self.assertEqual(len({line["line_id"] for line in lines}), 4)
        merged = next(line for line in lines if line["count"] == 2)
        self.assertEqual(merged["first_seen"], "2026-03-26 10:00:00")
        self.assertEqual(merged["last_seen"], "2026-03-26 10:01:00")

    @patch("tools.account_security_monitor.ip_trace_request")
    def test_account_security_auto_trace_uses_each_ip_first_and_last(self, trace_request):
        trace_request.side_effect = lambda ip, start_time, end_time, gid: {
            "trace_info": {"ip": ip, "time_window": f"{start_time} ~ {end_time}"}
        }
        result = _auto_trace_account_security_ips(
            {"data": [
                {"uiscrip": "10.0.0.1", "@timestamp": "2026-03-26 10:00:00"},
                {"uiscrip": "10.0.0.1", "@timestamp": "2026-03-26 11:00:00"},
                {"uiscrip": "10.0.0.2", "@timestamp": "2026-03-26 12:00:00"},
                {"uiscrip": "10.0.0.2", "@timestamp": "2026-03-26 13:00:00"},
            ]},
            start_time="2026-03-26 08:00:00",
            end_time="2026-03-26 14:00:00",
            gid="19936",
        )
        self.assertEqual(trace_request.call_count, 2)
        windows = {(call.kwargs["ip"], call.kwargs["start_time"], call.kwargs["end_time"]) for call in trace_request.call_args_list}
        self.assertIn(("10.0.0.1", "2026-03-26 09:30:00", "2026-03-26 11:30:00"), windows)
        self.assertIn(("10.0.0.2", "2026-03-26 11:30:00", "2026-03-26 13:30:00"), windows)

    @patch("tools.network_attack_detection.ip_trace_request")
    def test_network_auto_trace_uses_each_ip_first_and_last(self, trace_request):
        trace_request.side_effect = lambda ip, start_time, end_time, gid: {
            "trace_info": {"ip": ip, "time_window": f"{start_time} ~ {end_time}"}
        }
        result = _auto_trace_network_attack_ips(
            {"data": [
                {"source.ip": "10.0.0.1", "@timestamp": "2026-03-26T02:00:00Z"},
                {"source.ip": "10.0.0.1", "@timestamp": "2026-03-26T03:00:00Z"},
                {"source.ip": "10.0.0.2", "@timestamp": "2026-03-26T04:00:00Z"},
                {"source.ip": "10.0.0.2", "@timestamp": "2026-03-26T05:00:00Z"},
            ]},
            start_time="2026-03-26 00:00:00",
            end_time="2026-03-26 06:00:00",
            gid="19936",
        )
        self.assertEqual(trace_request.call_count, 2)
        windows = {(call.kwargs["ip"], call.kwargs["start_time"], call.kwargs["end_time"]) for call in trace_request.call_args_list}
        self.assertIn(("10.0.0.1", "2026-03-26 09:30:00", "2026-03-26 11:30:00"), windows)
        self.assertIn(("10.0.0.2", "2026-03-26 11:30:00", "2026-03-26 13:30:00"), windows)


if __name__ == "__main__":
    unittest.main()
