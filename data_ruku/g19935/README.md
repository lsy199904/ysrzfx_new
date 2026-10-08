# gid 19935 sample import

This directory is isolated from the original `data_ruku/*.json` samples. It
contains data for **gid 19935** only.

The records represent **2026-03-25 Asia/Shanghai (CST)**. Stored
`@timestamp` values and the FortiGate syslog timestamps are UTC, covering
`2026-03-24T16:00:00Z` through `2026-03-25T15:59:59Z`.

Generated counts are 36 brute-force records, 30 network-attack records, 24
account-change records, and 24 system-security records. The prepared files
retain both the raw FortiGate `message` and the normalized fields consumed by
the current PPL templates.

## Generate or regenerate

```bash
python3 data_ruku/g19935/generate_samples.py
```

This writes only `data_ruku/g19935/` files and never changes the existing
gid 19936 samples.

## Import into a separate index

Use the existing importer with the four files in this directory. The target
index is deliberately separate from `log_g19936_fortinet_fortigate`:

```bash
python3 data_ruku/ingest_opensearch.py \
  data_ruku/g19935/account_security_samples.json \
  --index log_g19935_fortinet_fortigate
python3 data_ruku/ingest_opensearch.py \
  data_ruku/g19935/brute_force_samples.json \
  --index log_g19935_fortinet_fortigate
python3 data_ruku/ingest_opensearch.py \
  data_ruku/g19935/network_attack_samples.json \
  --index log_g19935_fortinet_fortigate
python3 data_ruku/ingest_opensearch.py \
  data_ruku/g19935/system_security_samples.json \
  --index log_g19935_fortinet_fortigate
```

Do not use `--recreate` against the existing gid 19936 index. The generated
network records use public source IPs and the account/system records include
the exact `ui`, `cfgpath`, and `logdesc` values required by the current PPL
templates, so all four scenarios have queryable hits after Pipeline ingest.
