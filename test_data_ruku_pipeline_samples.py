import json
import shlex
import unittest
from pathlib import Path

from data_ruku.prepare_pipeline_samples import prepare_document


DATA_DIR = Path(__file__).parent / "data_ruku"
RAW_DIR = DATA_DIR / "raw_samples"


def load_raw(name):
    return json.loads((RAW_DIR / name).read_text(encoding="utf-8"))


def parse_kv_message(message):
    # Values in the fixture are FortiGate KV strings; shlex handles quoted msg/ui.
    fields = {}
    for token in shlex.split(message)[2:]:
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    return fields


class PipelineSampleTests(unittest.TestCase):
    def test_all_pipeline_inputs_keep_document_counts(self):
        expected = {
            "account_security_samples.json": 515,
            "brute_force_samples.json": 500,
            "network_attack_samples.json": 500,
            "system_security_samples.json": 500,
        }
        for name, count in expected.items():
            raw = load_raw(name)
            prepared = [prepare_document(item, name.removesuffix("_samples.json")) for item in raw]
            self.assertEqual(len(prepared), count)
            self.assertTrue(all(item["message"] for item in prepared))

    def test_brute_force_input_has_ppl_fields(self):
        raw = load_raw("brute_force_samples.json")
        prepared = [prepare_document(item, "brute_force") for item in raw]
        fields = parse_kv_message(prepared[0]["message"])
        self.assertEqual(fields["type"], "logon")
        self.assertEqual(fields["subtype"], "system")
        self.assertEqual(fields["action"], "login")
        self.assertEqual(fields["status"], "failed")
        self.assertTrue(fields["reason"])

    def test_network_input_has_attack_ppl_fields(self):
        raw = load_raw("network_attack_samples.json")
        prepared = [prepare_document(item, "network_attack") for item in raw]
        fields = parse_kv_message(prepared[0]["message"])
        self.assertEqual(fields["type"], "utm")
        self.assertEqual(fields["subtype"], "ips")
        self.assertEqual(fields["level"], "alert")
        self.assertEqual(fields["severity"], "high")
        self.assertTrue(fields["srcip"])
        self.assertTrue(fields["dstip"])

    def test_account_traffic_input_keeps_response_chain_fields(self):
        raw = load_raw("account_security_samples.json")
        traffic = next(item for item in raw if item.get("event", {}).get("action") == "traffic")
        fields = parse_kv_message(prepare_document(traffic, "account_security")["message"])
        self.assertEqual(fields["type"], "traffic")
        self.assertEqual(fields["dstip"], traffic["destination"]["ip"])
        self.assertEqual(fields["dstport"], str(traffic["destination"]["port"]))
        self.assertEqual(fields["policyid"], str(traffic["rule"]["id"]))
        self.assertEqual(fields["policyname"], traffic["rule"]["name"])

    def test_account_and_system_inputs_keep_graph_actions(self):
        for name, scenario in [
            ("account_security_samples.json", "account_security"),
            ("system_security_samples.json", "system_security"),
        ]:
            raw = load_raw(name)
            prepared = [prepare_document(item, scenario) for item in raw]
            for item, original in zip(prepared, raw):
                fields = parse_kv_message(item["message"])
                self.assertTrue(fields["subtype"])
                self.assertEqual(fields["action"], original["event"]["action"])
                self.assertTrue(fields["srcip"])
                self.assertTrue(fields["msg"])

    def test_syslog_host_uses_ip_not_device_name(self):
        for name, scenario in [
            ("account_security_samples.json", "account_security"),
            ("brute_force_samples.json", "brute_force"),
            ("network_attack_samples.json", "network_attack"),
            ("system_security_samples.json", "system_security"),
        ]:
            raw = load_raw(name)
            prepared = prepare_document(raw[0], scenario)
            header = prepared["message"].split(maxsplit=2)
            expected_host = raw[0]["source"]["ip"] or raw[0]["destination"]["ip"]
            self.assertEqual(header[1], expected_host)


if __name__ == "__main__":
    unittest.main()
