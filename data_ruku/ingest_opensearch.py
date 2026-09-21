#!/usr/bin/env python3
"""Bulk-load Pipeline-shaped FortiGate samples into OpenSearch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from opensearchpy import OpenSearch, helpers


DEFAULT_INDEX = "log_g19936_fortinet_fortigate"
DATA_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_FILE = str(DATA_DIR / "brute_force_samples.json")
DEFAULT_SAMPLE_FILES = tuple(
    DATA_DIR / filename
    for filename in (
        "account_security_samples.json",
        "brute_force_samples.json",
        "network_attack_samples.json",
        "system_security_samples.json",
    )
)

INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
    },
    "mappings": {
        "dynamic": True,
        "properties": {
            "@timestamp": {"type": "date"},
            "@gid": {"type": "keyword"},
            "msg": {"type": "text"},
            "source": {
                "properties": {
                    "ip": {"type": "ip"},
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    },
                }
            },
            "destination": {
                "properties": {
                    "ip": {"type": "ip"},
                }
            },
            "event": {
                "properties": {
                    "action": {"type": "keyword"},
                    "reason": {"type": "keyword"},
                }
            },
            "fortinet": {
                "properties": {
                    "firewall": {
                        "properties": {
                            "subtype": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "msg": {"type": "text"},
                        }
                    }
                }
            },
            "observer": {
                "properties": {
                    "name": {"type": "keyword"},
                }
            },
        },
    },
}


def load_documents(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a JSON array")
    if not all(isinstance(document, dict) for document in payload):
        raise ValueError(f"Every item in {path} must be a JSON object")
    return payload


def make_document_id(document: dict[str, Any], position: int) -> str:
    """Create a stable ID so rerunning the import updates rather than duplicates."""
    raw = json.dumps(
        {"position": position, "document": document},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def bulk_actions(
    documents: Iterable[dict[str, Any]], index: str
) -> Iterable[dict[str, Any]]:
    for position, document in enumerate(documents):
        yield {
            "_op_type": "create",
            "_index": index,
            "_id": make_document_id(document, position),
            "_source": document,
        }


def create_client() -> OpenSearch:
    url = os.getenv("OPENSEARCH_URL")
    if not url:
        scheme = os.getenv("ES_SCHEME", "https")
        host = os.getenv("ES_HOST", "localhost")
        port = os.getenv("ES_PORT", "9200")
        url = f"{scheme}://{host}:{port}"

    username = os.getenv("OPENSEARCH_USERNAME") or os.getenv("ES_USER")
    password = os.getenv("OPENSEARCH_PASSWORD") or os.getenv("ES_PASSWORD")

    verify_value = os.getenv("OPENSEARCH_VERIFY_CERTS")
    if verify_value is None:
        # The application .env uses ES_VERIFY_SSL, while this importer used
        # OPENSEARCH_VERIFY_CERTS. Support both names consistently.
        verify_value = os.getenv("ES_VERIFY_SSL", "true")
    verify_certs = verify_value.lower() in {"1", "true", "yes"}

    if not username or not password:
        raise RuntimeError(
            "Set OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD before running."
        )

    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
        raise ValueError(
            "OPENSEARCH_URL must look like https://host:9200 or http://host:9200."
        )

    ca_certs = os.getenv("OPENSEARCH_CA_CERTS")
    return OpenSearch(
        hosts=[
            {
                "host": parsed_url.hostname,
                "port": parsed_url.port
                or (443 if parsed_url.scheme == "https" else 9200),
            }
        ],
        http_auth=(username, password),
        http_compress=True,
        use_ssl=parsed_url.scheme == "https",
        verify_certs=verify_certs,
        ssl_assert_hostname=verify_certs,
        ssl_show_warn=not verify_certs,
        ca_certs=ca_certs,
        timeout=int(os.getenv("OPENSEARCH_TIMEOUT", "60")),
        max_retries=3,
        retry_on_timeout=True,
    )


def ensure_index(client: OpenSearch, index: str, recreate: bool) -> None:
    if recreate and client.indices.exists(index=index):
        client.indices.delete(index=index)

    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=INDEX_MAPPING)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bulk-load a JSON array into OpenSearch."
    )
    parser.add_argument(
        "data_file",
        nargs="?",
        default=DEFAULT_DATA_FILE,
        help=f"JSON array file (default: {DEFAULT_DATA_FILE})",
    )
    parser.add_argument(
        "--index",
        default=DEFAULT_INDEX,
        help=f"OpenSearch index name (default: {DEFAULT_INDEX})",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=100,
        help="Number of documents per bulk request (default: 100)",
    )
    parser.add_argument(
        "--all",
        dest="import_all",
        action="store_true",
        help="Import all four prepared scenario files from the current directory.",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and recreate the target index before importing.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.chunk_size < 1:
        raise ValueError("--chunk-size must be at least 1")

    data_files = (
        list(DEFAULT_SAMPLE_FILES)
        if args.import_all
        else [Path(args.data_file).expanduser()]
    )
    for data_file in data_files:
        if not data_file.is_file():
            raise FileNotFoundError(f"Input file does not exist: {data_file}")

    client = create_client()
    client.info()

    for position, data_file in enumerate(data_files):
        documents = load_documents(data_file)

        # Skip manual index creation — DataStream auto-creates on first write,
        # and an existing index template (log_fortinet_fortigate) manages this name.
        try:
            ensure_index(client, args.index, args.recreate and position == 0)
        except Exception as e:
            err_str = str(e).lower()
            if "data stream" in err_str or "index template" in err_str:
                print(f"Detected managed index/stream, skipping manual creation: {e}")
            else:
                raise

        success, failed = helpers.bulk(
            client,
            bulk_actions(documents, args.index),
            chunk_size=args.chunk_size,
            raise_on_error=False,
            raise_on_exception=True,
        )

        print(f"OpenSearch: {url_for_log()}")
        print(f"Index: {args.index}")
        print(f"Input: {data_file}")
        print(f"Documents read: {len(documents)}")
        print(f"Documents indexed: {success}")
        print(f"Documents failed: {len(failed)}")
        if failed:
            print(json.dumps(failed[:3], ensure_ascii=False, indent=2))
            return 1
    return 0


def url_for_log() -> str:
    """Return the configured endpoint without printing credentials."""
    value = os.getenv("OPENSEARCH_URL")
    if value:
        return value
    return f"{os.getenv('ES_SCHEME', 'https')}://{os.getenv('ES_HOST', 'localhost')}:{os.getenv('ES_PORT', '9200')}"


if __name__ == "__main__":
    raise SystemExit(main())
