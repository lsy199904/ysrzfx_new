#!/usr/bin/env python3
"""Bulk-load FortiGate brute-force samples into OpenSearch."""

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
DEFAULT_DATA_FILE = "brute_force_samples.json"

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
    url = os.getenv("OPENSEARCH_URL", "https://localhost:9200")
    username = os.getenv("OPENSEARCH_USERNAME")
    password = os.getenv("OPENSEARCH_PASSWORD")
    verify_certs = os.getenv("OPENSEARCH_VERIFY_CERTS", "true").lower() in {
        "1",
        "true",
        "yes",
    }

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
        "--recreate",
        action="store_true",
        help="Delete and recreate the target index before importing.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_file = Path(args.data_file).expanduser()

    if not data_file.is_file():
        raise FileNotFoundError(f"Input file does not exist: {data_file}")
    if args.chunk_size < 1:
        raise ValueError("--chunk-size must be at least 1")

    documents = load_documents(data_file)
    client = create_client()
    client.info()

    # Skip manual index creation — DataStream auto-creates on first write,
    # and an existing index template (log_fortinet_fortigate) manages this name.
    try:
        ensure_index(client, args.index, args.recreate)
    except Exception as e:
        err_str = str(e).lower()
        if "data stream" in err_str or "index template" in err_str:
            # This name is managed by an index template → auto-creates DataStream
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

    print(f"OpenSearch: {os.getenv('OPENSEARCH_URL', 'https://localhost:9200')}")
    print(f"Index: {args.index}")
    print(f"Input: {data_file}")
    print(f"Documents read: {len(documents)}")
    print(f"Documents indexed: {success}")
    print(f"Documents failed: {len(failed)}")
    if failed:
        print(json.dumps(failed[:3], ensure_ascii=False, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
