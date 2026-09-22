import json
import sys
import types
import unittest

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

from tools.brute_force import _get_ip_first_attack_time, _normalize_attack_time
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
        self.assertGreater(len(graph["nodes"]), 0)
        self.assertIn(
            "device_GuZ_OFFICE_500E",
            {node["id"] for node in graph["nodes"]},
        )

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


if __name__ == "__main__":
    unittest.main()
