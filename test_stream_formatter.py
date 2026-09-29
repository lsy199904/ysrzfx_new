import unittest

from stream_formatter import (
    ThoughtStreamParser,
    clean_final_answer,
    split_thoughts,
    thought_event_to_answer,
)


class StreamFormatterTests(unittest.TestCase):
    def test_split_tags_across_tokens(self):
        parser = ThoughtStreamParser()
        events = []
        for token in ["<th", "ink>分析", "用户问题", "</thi", "nk>", "\n## 1. Summary"]:
            events.extend(parser.feed(token))
        events.extend(parser.flush())

        self.assertEqual("分析用户问题", "".join(e.get("think", "") for e in events))
        self.assertTrue(any(e.get("think_start") for e in events))
        self.assertTrue(any(e.get("think_end") for e in events))

    def test_final_answer_removes_embedded_thought(self):
        thought, answer = split_thoughts(
            "<think>先检查工具结果</think>\n\n**查询结果**\n\n- 总数：3"
        )
        self.assertEqual(thought, "先检查工具结果")
        self.assertEqual(answer, "**查询结果**\n\n- 总数：3")
        self.assertEqual(clean_final_answer("<think>hidden</think>**Final**"), "**Final**")

    def test_truncated_thought_never_leaks_open_tag(self):
        self.assertEqual(clean_final_answer("<think>incomplete reasoning"), "")

    def test_multiple_thought_blocks_are_streamed(self):
        parser = ThoughtStreamParser()
        events = parser.feed("<think>first</think>text<think>second</think>")
        self.assertEqual([e["think"] for e in events if e.get("think")], ["first", "second"])
        self.assertEqual(sum(bool(e.get("think_start")) for e in events), 2)
        self.assertEqual(sum(bool(e.get("think_end")) for e in events), 2)

    def test_legacy_answer_protocol_has_explicit_boundaries(self):
        self.assertEqual(thought_event_to_answer({"think_start": True}), "<think>")
        self.assertEqual(thought_event_to_answer({"think": "分析"}), "分析")
        self.assertEqual(thought_event_to_answer({"think_end": True}), "</think>")


if __name__ == "__main__":
    unittest.main()
