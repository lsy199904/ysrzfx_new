# -*- coding: utf-8 -*-
"""Capture Agent SSE streams for bilingual and permission test cases."""
import argparse
import json
import os
import time
from datetime import datetime
from typing import Iterable, Optional

import requests

from config import APP_HOST, APP_PORT


DEFAULT_ALLOWED_GIDS = ["12345", "19936", "65789"]


def _decode_line(line) -> str:
    if isinstance(line, bytes):
        return line.decode("utf-8", errors="replace")
    return str(line)


def iter_sse_events(lines: Iterable[str]):
    """Yield ``(event_name, data_text, raw_lines)`` from SSE lines."""
    event_name = "message"
    data_lines = []
    raw_lines = []

    def flush():
        nonlocal event_name, data_lines, raw_lines
        if not data_lines:
            event_name = "message"
            raw_lines = []
            return None
        result = (event_name, "\n".join(data_lines), list(raw_lines))
        event_name = "message"
        data_lines = []
        raw_lines = []
        return result

    for line in lines:
        line = _decode_line(line).rstrip("\r")
        if line == "":
            event = flush()
            if event:
                yield event
            continue
        raw_lines.append(line)
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].lstrip() or "message"
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())

    event = flush()
    if event:
        yield event


def _parse_event(event_name: str, data_text: str, raw_lines: list) -> dict:
    try:
        data = json.loads(data_text)
        parse_error = None
    except json.JSONDecodeError as exc:
        data = data_text
        parse_error = str(exc)
    return {
        "event": event_name,
        "data": data,
        "raw_sse": "\n".join(raw_lines),
        **({"parse_error": parse_error} if parse_error else {}),
    }


def _summarize_events(events: list) -> dict:
    json_events = [event["data"] for event in events if isinstance(event.get("data"), dict)]
    final_answers = [
        event["data"]["final_answer"]
        for event in events
        if "final_answer" in event.get("data", {})
    ]
    return {
        "event_count": len(events),
        "has_final_answer": bool(final_answers),
        "final_answer": final_answers[-1] if final_answers else "",
        "answer_event_count": sum("answer" in data for data in json_events),
        "tools_event_count": sum("tools" in data for data in json_events),
        "graph_data_event_count": sum(data.get("type") == "graph_data" for data in json_events),
    }


def call_and_save_stream_output(
    session_id: str,
    user_input: str,
    output_dir: str = "./output",
    lang: str = "zh",
    output_file: Optional[str] = None,
    login_account: str = "test",
    is_admin: bool = False,
    allowed_gids: Optional[list] = None,
    expected_final_answer: Optional[bool] = None,
    base_url: Optional[str] = None,
):
    """Call ``/agentchat`` and save the complete parsed SSE stream."""
    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    agent_base_url = (
        base_url
        or os.environ.get("AGENT_URL")
        or f"http://127.0.0.1:{APP_PORT}"
    ).rstrip("/")
    url = f"{agent_base_url}/agentchat"
    payload = {
        "session_id": session_id,
        "user_input": user_input.strip(),
        "login_account": login_account,
        "is_admin": is_admin,
        "allowed_gids": DEFAULT_ALLOWED_GIDS if allowed_gids is None else allowed_gids,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_file:
        json_file = os.path.join(output_dir, output_file)
        txt_file = os.path.join(output_dir, os.path.splitext(output_file)[0] + ".txt")
    else:
        json_file = os.path.join(output_dir, f"stream_{timestamp}_{lang}.jsonl")
        txt_file = os.path.join(output_dir, f"stream_{timestamp}_{lang}.txt")

    print(f"开始调用接口 ({lang.upper()})...")
    print(f"问题：{user_input}")
    print(f"输出文件：{json_file}")
    print("-" * 60)

    events = []
    status_code = None
    response_error = None
    try:
        with requests.post(url, json=payload, stream=True, timeout=(10, 300)) as response:
            status_code = response.status_code
            if response.status_code != 200:
                response_error = response.text[:2000]
            else:
                for event_name, data_text, raw_lines in iter_sse_events(
                    response.iter_lines(decode_unicode=True, chunk_size=1)
                ):
                    event = _parse_event(event_name, data_text, raw_lines)
                    events.append(event)
                    data = event["data"]
                    if not isinstance(data, dict):
                        continue
                    if "answer" in data:
                        print(data["answer"], end="", flush=True)
                    elif "tools" in data:
                        print("\n" + "-" * 50)
                        for item in data["tools"]:
                            print(item)
                        print("-" * 50)
                    elif "final_answer" in data:
                        print("\n" + "=" * 50)
                        print("最终答案：" if lang == "zh" else "Final Answer:")
                        print(data["final_answer"])
                    elif data.get("type") == "graph_data":
                        print("\n[graph_data event]")
    except requests.RequestException as exc:
        response_error = str(exc)

    elapsed_time = time.time() - start_time
    summary = _summarize_events(events)
    result = {
        "session_id": session_id,
        "user_input": user_input,
        "request_payload": payload,
        "http_status": status_code,
        "elapsed_seconds": round(elapsed_time, 3),
        "expected_final_answer": expected_final_answer,
        "actual_has_final_answer": summary["has_final_answer"],
        "expectation_matches": (
            None
            if expected_final_answer is None
            else expected_final_answer == summary["has_final_answer"]
        ),
        "response_error": response_error,
        **summary,
        "events": events,
    }

    with open(json_file, "w", encoding="utf-8") as file:
        if output_file:
            json.dump(result, file, ensure_ascii=False, indent=2)
        else:
            for event in events:
                data = event.get("data")
                if isinstance(data, dict) and "answer" in data:
                    # 只输出 answer 字段
                    file.write(json.dumps({"answer": data["answer"]}, ensure_ascii=False) + "\n")
                else:
                    file.write(json.dumps(data, ensure_ascii=False) + "\n")

    with open(txt_file, "w", encoding="utf-8") as file:
        file.write("=" * 60 + "\n")
        file.write(f"Agent SSE Stream ({lang.upper()})\n")
        file.write("=" * 60 + "\n\n")
        file.write(f"Session ID: {session_id}\n")
        file.write(f"User Input: {user_input}\n")
        file.write(f"HTTP Status: {status_code}\n")
        file.write(f"SSE Events: {len(events)}\n")
        file.write(f"Has final_answer: {summary['has_final_answer']}\n")
        if response_error:
            file.write(f"Response Error: {response_error}\n")
        file.write("\n" + "-" * 60 + "\n")
        for event in events:
            file.write(json.dumps(event["data"], ensure_ascii=False))
            file.write("\n")

    print("\n" + "=" * 60)
    print(f"HTTP 状态码：{status_code}")
    print(f"SSE 事件数：{len(events)}")
    print(f"是否有 final_answer：{summary['has_final_answer']}")
    if expected_final_answer is not None:
        print(f"期望是否有 final_answer：{expected_final_answer}")
        print(f"期望匹配：{result['expectation_matches']}")
    print(f"JSON：{json_file}")
    print(f"TXT：{txt_file}")

    return {"json_file": json_file, "txt_file": txt_file, **result}


FOUR_CASES = [
    {
        "case": "a",
        "lang": "zh",
        "question": "2026年gid19936的3月26日有哪些暴力破解记录",
        "output_file": "nofinal_answer_ch.json",
        "expected_final_answer": False,
    },
    {
        "case": "b",
        "lang": "en",
        "question": "What are the brute force attack records for gid 19936 on March 26, 2026?",
        "output_file": "nofinal_answer_en.json",
        "expected_final_answer": False,
    },
    {
        "case": "c",
        "lang": "zh",
        "question": "查询 gid 99999 的暴力破解日志",
        "output_file": "final_answer_ch.json",
        "expected_final_answer": True,
    },
    {
        "case": "d",
        "lang": "en",
        "question": "What are the brute force attack logs for gid 99999?",
        "output_file": "final_answer_en.json",
        "expected_final_answer": True,
    },
]


def run_four_cases(output_dir: str = "./output", base_url: Optional[str] = None):
    """Run the four requested bilingual and permission cases."""
    run_id = datetime.now().strftime("%Y%m%d%H%M%S")
    results = []
    for case in FOUR_CASES:
        results.append(
            call_and_save_stream_output(
                session_id=f"sse_case_{case['case']}_{run_id}",
                user_input=case["question"],
                output_dir=output_dir,
                lang=case["lang"],
                output_file=case["output_file"],
                login_account="test",
                is_admin=False,
                allowed_gids=DEFAULT_ALLOWED_GIDS,
                expected_final_answer=case["expected_final_answer"],
                base_url=base_url,
            )
        )
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture four Agent SSE test streams")
    parser.add_argument("--output-dir", default="./output", help="Directory for the four JSON/TXT files")
    parser.add_argument(
        "--base-url",
        default=None,
        help="Agent base URL, e.g. http://127.0.0.1:8000 or http://10.180.158.23:8000",
    )
    args = parser.parse_args()
    try:
        run_four_cases(args.output_dir, args.base_url)
    except KeyboardInterrupt:
        print("\n测试已中断")
    except Exception as exc:
        print(f"调用异常：{exc}")
