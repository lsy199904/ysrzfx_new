import json
import sys
import types
import unittest

# Keep these pure localization tests runnable in the lightweight development
# interpreter used on the desktop; production already installs both packages.
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

from tools.free_query import _free_query_labels, _is_chinese, free_query_request
from tools.tool_base import ToolExecutor
from stream_formatter import contains_cjk, detect_response_language


def _contains_cjk(value):
    return any("\u4e00" <= char <= "\u9fff" for char in str(value or ""))


class LanguageLocalizationTests(unittest.TestCase):
    def test_request_language_ignores_technical_identifiers(self):
        self.assertEqual(
            detect_response_language("查询 gid19936 的 brute_force_request 记录"),
            "zh",
        )
        self.assertEqual(
            detect_response_language(
                "What are the brute force attack records for gid 19936?"
            ),
            "en",
        )
        self.assertTrue(contains_cjk("中文"))
        self.assertFalse(contains_cjk("English"))

    def test_english_request_detection_and_labels(self):
        self.assertFalse(_is_chinese("Show failed login records for today"))
        labels = _free_query_labels(False)
        for value in labels.values():
            self.assertFalse(_contains_cjk(value), value)

    def test_chinese_request_keeps_chinese_labels(self):
        self.assertTrue(_is_chinese("查询今天的登录失败记录"))
        labels = _free_query_labels(True)
        self.assertTrue(_contains_cjk(labels["cache_title"]))

    def test_tool_steps_are_english_for_english_request(self):
        executor = ToolExecutor.__new__(ToolExecutor)
        executor.user_problem = "Show failed login records for today"
        executor.start_time = None
        executor.end_time = None
        executor.filter_ip = None
        executor.filter_user = None
        executor.index_check_steps = None

        steps = executor._build_steps(
            "search source=`log_g*_fortinet_fortigate` | head 100",
            200,
            "",
            2,
            {"compressed": False},
        )
        for step in steps:
            self.assertFalse(_contains_cjk(step["title"]), step)
            self.assertFalse(_contains_cjk(step["detail"]), step)

    def test_empty_free_query_response_keeps_default_language(self):
        result = json.loads(free_query_request(user_problem=""))
        # An empty request has no language signal; the helper defaults to the non-CJK branch.
        self.assertFalse(_contains_cjk(result["error"]))


if __name__ == "__main__":
    unittest.main()
