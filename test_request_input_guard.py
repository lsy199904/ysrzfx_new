import unittest

from tools.request_input_guard import canonicalize_action_input, extract_explicit_gid


class RequestInputGuardTests(unittest.TestCase):
    def test_extracts_gid_without_dropping_digits(self):
        self.assertEqual(extract_explicit_gid("查询 gid19936 的暴力破解记录"), "19936")
        self.assertEqual(extract_explicit_gid("查询用户组 19936 的日志"), "19936")

    def test_restores_user_problem_and_gid_from_request(self):
        original = "2026年gid19936的3月26日有哪些暴力破解记录"
        normalized, changes = canonicalize_action_input(
            {
                "user_problem": "2026年gid1936的3月26日有哪些暴力破解记录",
                "start_time": "2026-03-26",
                "end_time": "2026-03-26",
                "gid": "1936",
            },
            original,
        )
        self.assertEqual(normalized["user_problem"], original)
        self.assertEqual(normalized["gid"], "19936")
        self.assertEqual(set(changes), {"user_problem", "gid"})

    def test_clears_model_gid_when_request_has_no_gid(self):
        normalized, changes = canonicalize_action_input(
            {"user_problem": "查询今天的暴力破解记录", "gid": "1936"},
            "查询今天的暴力破解记录",
        )
        self.assertIsNone(normalized["gid"])
        self.assertEqual(changes["gid"], ("1936", None))


if __name__ == "__main__":
    unittest.main()
