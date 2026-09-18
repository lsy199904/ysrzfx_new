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
from tools.ip_trace import IP_TRACE_PPL_TEMPLATE, _build_trace_result


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
        self.assertNotIn("attack_src", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("source.ip", IP_TRACE_PPL_TEMPLATE)
        self.assertIn("destination.ip", IP_TRACE_PPL_TEMPLATE)

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


if __name__ == "__main__":
    unittest.main()
