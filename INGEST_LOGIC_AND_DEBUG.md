# Fortinet Log Ingestion Logic & Debugging Request

## 1. Task Description
- **Goal**: Ingest Fortinet Fortigate logs into OpenSearch index `log_g19936_fortinet_fortigate`.
- **Data Source**: JSON files located in `data_ruku/brute_force_samples.json`.
- **Status**: 2,000 documents have been successfully indexed (based on script output).
- **Current Problem**: PPL queries return empty values (`-`) for nested fields like `source.user.name`, `event.action`, and `event.reason`, even though the JSON sample clearly contains these fields.

---

## 2. Ingestion Script Logic (`ingest_opensearch.py`)
- **Source**: `data_ruku/ingest_opensearch.py`
- **Core Logic**:
  1.  Loads JSON array from file.
  2.  Checks if index exists; if not, creates it using `INDEX_MAPPING`.
  3.  Uses `helpers.bulk` to index documents.
  4.  **ID Generation**: Uses SHA256 of the document content + position to ensure idempotent upserts.
- **Mapping**:
  - The script defines a custom `INDEX_MAPPING` in Python which sets `source.user.name` to `keyword` type.
  - `dynamic: true` is enabled, meaning unmapped fields will be auto-created (likely as `text` or `long`).

## 3. Execution Command
The data was imported using the following command (or similar):
```bash
python3 data_ruku/ingest_opensearch.py data_ruku/brute_force_samples.json --index log_g19936_fortinet_fortigate --recreate
```

## 4. Mapping Configuration (`INDEX_MAPPING` in script)
Relevant parts of the mapping definition:
```python
INDEX_MAPPING = {
    "settings": { ... },
    "mappings": {
        "dynamic": True,
        "properties": {
            "@timestamp": {"type": "date"},
            "@gid": {"type": "keyword"},
            "source": {
                "properties": {
                    "ip": {"type": "ip"},
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},  # Explicitly defined
                        }
                    },
                }
            },
            "event": {
                "properties": {
                    "action": {"type": "keyword"},  # Explicitly defined
                    "reason": {"type": "keyword"},   # Explicitly defined
                }
            },
            "fortinet": {
                "properties": {
                    "firewall": {
                        "properties": {
                            "subtype": {"type": "keyword"},
                            "status": {"type": "keyword"},
                        }
                    }
                }
            },
        }
    }
}
```

## 5. Sample Data (`brute_force_samples.json`)
The input JSON structure explicitly includes the fields in question:
```json
{
  "@timestamp": "2026-03-25T16:00:00+00:00",
  "@gid": "19936",
  "source": {
    "user": {
      "name": "zhang_san"
    },
    "ip": "10.180.97.12"
  },
  "event": {
    "action": "login",
    "reason": "wrong_password"
  },
  "fortinet": { ... }
}
```

## 6. Observed PPL Query Issue
**Query:**
```ppl
search source=`log_g19936_fortinet_fortigate`
  @timestamp >= '2026-03-26T10:33:21'
  ...
| fields @timestamp, source.ip, source.user.name, event.action ...
| where attack_src = '10.180.120.160'
```

**Result:**
- `source.ip`: Returns IP correctly (e.g., `10.180.120.160`).
- `source.user.name`: Returns `-` (empty/missing).
- `event.action`: Returns `-` (empty/missing).
- `event.reason`: Returns `-` (empty/missing).

## 7. Analysis Request for Codex
1.  **Why are mapped fields (`source.user.name`, `event.action`) returning `-` in PPL results when the source JSON clearly contains them?**
2.  Could the `dynamic: true` setting be overriding the nested `source.user` structure or changing the field path (e.g., flattening)?
3.  Is the PPL syntax `fields source.user.name` correct for OpenSearch? (Some versions require `source.user` as object or specific nested handling).
4.  Suggest a reliable verification query (DSL or SQL) to confirm if the data actually exists in the index under these paths.
