from __future__ import annotations
import json
import logging
from langchain.agents import Tool, AgentOutputParser
from langchain.prompts import StringPromptTemplate
from typing import List
from langchain.schema import AgentAction, AgentFinish
from pydantic.schema import model_schema

# 复用 agent_chat 模块中已配置好的 app_logger（单例）
app_logger = logging.getLogger("agent_chat")

_MAX_OBSERVATION_CHARS = 12000
_MAX_OBSERVATION_FIELD_CHARS = 3000
_DROP_OBSERVATION_KEYS = {"graph_data", "render_lines"}
_DROPPED = object()


def _truncate_observation_text(value: str, limit: int = _MAX_OBSERVATION_FIELD_CHARS) -> str:
    """Keep both the beginning and end of a long tool field."""
    if len(value) <= limit:
        return value
    head = max(1, int(limit * 0.75))
    tail = max(1, limit - head)
    return f"{value[:head]}\n...[truncated {len(value) - limit} chars]...\n{value[-tail:]}"


def _compact_observation_value(value, key: str = "", depth: int = 0):
    """Remove graph payloads and bound raw log fields before the next LLM call."""
    if key in _DROP_OBSERVATION_KEYS:
        return _DROPPED
    if depth > 6:
        return _truncate_observation_text(str(value)) if isinstance(value, str) else str(value)

    if isinstance(value, dict):
        compacted = {}
        for child_key, child_value in value.items():
            child = _compact_observation_value(child_value, str(child_key), depth + 1)
            if child is not _DROPPED:
                compacted[child_key] = child
        return compacted

    if isinstance(value, list):
        # Raw data and per-IP trace details can be large; keep enough records
        # for a useful summary while leaving the full payload available to SSE.
        if key == "top_ip_records":
            limit = 30
        else:
            limit = 3 if key in {"data", "ip_details"} else 8
        compacted = []
        for item in value[:limit]:
            child = _compact_observation_value(item, key, depth + 1)
            if child is not _DROPPED:
                compacted.append(child)
        if len(value) > limit:
            compacted.append({"__truncated_items__": len(value) - limit})
        return compacted

    if isinstance(value, str):
        stripped = value.strip()
        # Trace activities are JSON strings nested inside the tool response.
        if key in {"activities", "output_str"} and stripped[:1] in {"{", "["}:
            try:
                nested = json.loads(stripped)
            except (TypeError, json.JSONDecodeError):
                nested = None
            if nested is not None:
                return _compact_observation_value(nested, key, depth + 1)
        return _truncate_observation_text(value)

    return value


def _prompt_field(record: dict, field: str):
    """Read flat or dotted fields while preparing the model observation."""
    if not isinstance(record, dict):
        return None
    if field in record and record[field] not in (None, ""):
        return record[field]
    value = record
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value if value not in (None, "") else None


def _prompt_ip(record: dict):
    """Return the attack-source field used by the specialized tools."""
    for field in ("attack_src", "source.ip", "srcip", "uiscrip", "remip"):
        value = _prompt_field(record, field)
        if value:
            return str(value)
    return None


def compact_observation_for_llm(observation: str) -> str:
    """Bound a tool observation used in the ReAct scratchpad.

    The callback still receives the original tool output, so graph data and
    complete records remain available to the frontend. Only the copy sent
    back to the model is compacted.
    """
    if not isinstance(observation, str) or not observation:
        return observation

    try:
        parsed = json.loads(observation)
    except (TypeError, json.JSONDecodeError):
        compacted_text = _truncate_observation_text(observation, _MAX_OBSERVATION_CHARS)
    else:
        if isinstance(parsed, dict):
            # Put summaries and query steps ahead of raw records.  This keeps
            # the useful explanation when a response contains hundreds of
            # records plus a large trace graph.
            # Put deterministic aggregate statistics before any sampled raw
            # records.  The model must never infer Top 3 from data[:3].
            priority_keys = (
                "ip_stats", "count", "compression", "steps", "ppl_query",
                "http_status", "error", "suggestion", "trace_info", "status",
                "message", "ip_count", "time_window",
            )
            projected = {
                key: parsed[key]
                for key in priority_keys
                if key in parsed
            }
            ip_stats = parsed.get("ip_stats")
            if isinstance(ip_stats, list):
                projected["ip_summary"] = {
                    "total_records": parsed.get("count", 0),
                    "unique_ip_count": len(ip_stats),
                    "top3": ip_stats[:3],
                }
            compression = parsed.get("compression")
            if isinstance(compression, dict):
                # Keep the pre-query summary explicitly available even when
                # the full compression object is shortened later.
                if compression.get("summary_text"):
                    projected["summary_text"] = compression["summary_text"]
                projected["compression_meta"] = {
                    key: compression.get(key)
                    for key in ("compressed", "original_count", "compressed_count")
                    if key in compression
                }

            if isinstance(ip_stats, list):
                records = parsed.get("data")
                if isinstance(records, list) and ip_stats:
                    top_ips = {
                        str(item.get("ip"))
                        for item in ip_stats[:3]
                        if isinstance(item, dict) and item.get("ip")
                    }
                    if top_ips:
                        projected["top_ip_records"] = [
                            record for record in records
                            if _prompt_ip(record) in top_ips
                        ][:30]

            if "data" in parsed:
                projected["data_sample"] = (
                    parsed["data"][:3]
                    if isinstance(parsed["data"], list)
                    else parsed["data"]
                )
                projected["data_note"] = (
                    "data_sample is incomplete and must not be used for Top 3, "
                    "counts, percentages, unique IP totals, or ranking. Use ip_summary/ip_stats."
                )
            compacted = _compact_observation_value(projected)
        else:
            compacted = _compact_observation_value(parsed)
        compacted_text = json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
        compacted_text = _truncate_observation_text(compacted_text, _MAX_OBSERVATION_CHARS)

    if compacted_text != observation:
        app_logger.info(
            "[Prompt Budget] tool observation compacted: %s -> %s chars",
            len(observation),
            len(compacted_text),
        )
    return compacted_text


class CustomPromptTemplate(StringPromptTemplate):
    """
    提示词处理的相关逻辑
    """
    template: str
    tools: List[Tool]

    def format(self, **kwargs) -> str:
        intermediate_steps = kwargs.pop("intermediate_steps")
        thoughts = ""
        for action, observation in intermediate_steps:
            action_log = _truncate_observation_text(
                getattr(action, "log", ""),
                _MAX_OBSERVATION_FIELD_CHARS,
            )
            thoughts += action_log
            compacted_observation = compact_observation_for_llm(observation)
            thoughts += f"\nObservation: {compacted_observation}\nThought: "
        kwargs["agent_scratchpad"] = thoughts

        def _fetch_tool_input_schema(_tool):
            """
            定义工具参数提取函数
            """
            _tool_schema = model_schema(_tool.args_schema) if _tool.args_schema else {}
            _properties = _tool_schema.get('properties', {})
            _schema = {}
            for _input_name in _properties.keys():
                _schema[_input_name] = _properties[_input_name]['description']
            return _schema

        kwargs["tools"] = "\n\n".join(
            [f"{tool.name}: {tool.description} ; input args: {_fetch_tool_input_schema(tool)}" for tool in self.tools])
        kwargs["tool_names"] = ", ".join([tool.name for tool in self.tools])
        return self.template.format(**kwargs)


class CustomOutputParser(AgentOutputParser):
    """
    对应的模型输出结果的解析 --> 决定是结束调用，还是继续调用 agent 方法

    简化后的逻辑：
    1. 检测 Action → AgentAction（继续调用工具）
    2. 检测 JSON（http_status 非 200）→ AgentFinish（兜底提示）
    3. 其他情况 → AgentFinish（LLM 总结或兜底）
    """

    # AgentOutputParser 是 Pydantic 模型。必须声明为模型字段，不能在
    # __init__ 中直接赋值，否则生产环境会因未声明字段中断 SSE 响应。
    is_chinese: bool = True
    # Request-owned text is authoritative for query scope. The model may not
    # rewrite identifiers such as gid while producing an Action.
    original_user_input: str = ""

    def _canonicalize_action_input(self, action_input: dict, tool: str) -> dict:
        """Prevent model output from changing the request's query scope."""
        if not self.original_user_input or not isinstance(action_input, dict):
            return action_input

        from tools.request_input_guard import canonicalize_action_input

        normalized, changes = canonicalize_action_input(
            action_input,
            self.original_user_input,
        )
        if changes:
            app_logger.warning(
                "[REQUEST_INPUT_GUARD] corrected tool=%s fields=%s",
                tool,
                list(changes.keys()),
            )
            for field, (model_value, source_value) in changes.items():
                app_logger.warning(
                    "[REQUEST_INPUT_GUARD] %s: model=%r, request=%r",
                    field,
                    model_value,
                    source_value,
                )
        return normalized

    def parse(self, llm_output: str) -> AgentFinish | tuple[dict[str, str], str] | AgentAction:
        """
        解析 LLM 输出，决定是继续调用工具还是结束

        Args:
            llm_output: LLM 的输出文本

        Returns:
            AgentAction: 继续调用工具
            AgentFinish: 结束调用，返回最终答案
        """
        import re

        # ========== 诊断日志：记录 LLM 原始输出 ==========
        app_logger.info(f"\n{'='*60}")
        app_logger.info(f"=== CustomOutputParser.parse DEBUG ===")
        app_logger.info(f"{'='*60}")
        app_logger.info(f"llm_output 总长度：{len(llm_output)}")
        app_logger.info(f"\n【完整 llm_output 内容】:\n{llm_output}\n【END llm_output】")


        # === 0. 清理思考模式标签（支持两种格式） ===
        # 格式 1: <think>...</think>
        # 格式 2: <antThinking>...</antThinking>
        # 格式 3: <thinking>...</thinking>
        # 这些推理内容会干扰 ReAct 格式解析，需要提取思考标签之后的有效内容
        _closed_thought_pattern = re.compile(
            r"<(?:think|antThinking|thinking)>.*?</(?:think|antThinking|thinking)>\s*",
            re.IGNORECASE | re.DOTALL,
        )
        _cleaned_output = _closed_thought_pattern.sub("", llm_output).strip()
        if _cleaned_output != llm_output.strip():
            app_logger.info("检测到完整思考块，已从 Action 解析文本中移除")
            llm_output = _cleaned_output

        _thought_close_tags = [
            '<think/>', '<antThinking/>', '<antThinking>', '</antThinking>',
            '<thinking/>', '<thinking>', '</thinking>',
        ]
        _first_close_pos = len(llm_output)
        _close_tag_used = None
        for _tag in _thought_close_tags:
            _pos = llm_output.find(_tag)
            if _pos != -1 and _pos < _first_close_pos:
                _first_close_pos = _pos
                _close_tag_used = _tag

        if _close_tag_used is not None:
            _after_thought = llm_output[_first_close_pos + len(_close_tag_used):].strip()
            if _after_thought:
                llm_output = _after_thought
                _tag_name = _close_tag_used.rstrip('/')
                app_logger.info(f"\n检测到 {_tag_name} 标签，提取 {_tag_name}> 之后的内容")
                app_logger.info(f"清理后 llm_output 长度：{len(llm_output)}")
                app_logger.info(f"清理后内容：{llm_output}")
            else:
                app_logger.info(f"\n⚠️ 检测到思考标签但标签后无内容（思考被截断），尝试恢复 Action/Answer")
                _inner_action_match = re.search(
                    r'(?:行动|Action)\s*[：:]\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                    llm_output, re.IGNORECASE
                )
                _natural_action_match = re.search(
                    r'(?:我应该使用|调用|使用|选择)\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                    llm_output
                )
                _recovered_action = None
                if _inner_action_match:
                    _recovered_action = _inner_action_match.group(1).strip()
                    app_logger.info(f"策略 A 命中 - 从 thinking 块提取 Action: {_recovered_action}")
                elif _natural_action_match:
                    _candidate = _natural_action_match.group(1).strip()
                    if '_request' in _candidate or _candidate in ['tool', 'search', 'query']:
                        _recovered_action = _candidate
                        app_logger.info(f"策略 B 命中 - 从自然语言提取 Action: {_recovered_action}")
                if _recovered_action:
                    llm_output = f"行动：{_recovered_action}\n行动输入：{{}}"
                    app_logger.info(f"重构为标准格式: {llm_output[:200]}")
                else:
                    _after_think = llm_output.split('<antThinking', 1)[-1].split('<thinking', 1)[-1].strip()
                    if _after_think and '<antThinking' not in _after_think and '<thinking' not in _after_think and len(_after_think) > 5:
                        llm_output = _after_think
                        app_logger.info(f"策略 C 命中 - 提取思考标签后的内容，长度：{len(llm_output)}")
                    else:
                        app_logger.info(f"所有策略均失败，返回截断提示")
                        interrupted_message = (
                            "抱歉，模型推理过程被中断，请重新提问。"
                            if self.is_chinese
                            else "Sorry, the model reasoning was interrupted. Please try again."
                        )
                        return AgentFinish(
                            return_values={"output": interrupted_message},
                            log=llm_output,
                        )
        elif (
            '<think>' in llm_output
            or '<antThinking' in llm_output
            or '<thinking' in llm_output
        ):
            # 只有思考开始标签没有结束标签，说明思考内容被截断
            app_logger.info(f"\n⚠️ 检测到未闭合思考标签（思考被截断），尝试恢复 Action/Answer")
            _inner_action_match = re.search(
                r'(?:行动|Action)\s*[：:]\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                llm_output, re.IGNORECASE
            )
            _natural_action_match = re.search(
                r'(?:我应该使用|调用|使用|选择)\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                llm_output
            )
            _recovered_action = None
            if _inner_action_match:
                _recovered_action = _inner_action_match.group(1).strip()
                app_logger.info(f"策略 A 命中 - 从 thinking 块提取 Action: {_recovered_action}")
            elif _natural_action_match:
                _candidate = _natural_action_match.group(1).strip()
                if '_request' in _candidate or _candidate in ['tool', 'search', 'query']:
                    _recovered_action = _candidate
                    app_logger.info(f"策略 B 命中 - 从自然语言提取 Action: {_recovered_action}")
            if _recovered_action:
                llm_output = f"行动：{_recovered_action}\n行动输入：{{}}"
                app_logger.info(f"重构为标准格式: {llm_output[:200]}")
            else:
                _after_think = (
                    llm_output.split('<antThinking', 1)[-1]
                    .split('<thinking', 1)[-1]
                    .split('<think>', 1)[-1]
                    .strip()
                )
                if (
                    _after_think
                    and '<antThinking' not in _after_think
                    and '<thinking' not in _after_think
                    and '<think>' not in _after_think
                    and len(_after_think) > 5
                ):
                    llm_output = _after_think
                    app_logger.info(f"策略 C 命中 - 提取思考标签后的内容，长度：{len(llm_output)}")
                else:
                    app_logger.info(f"所有策略均失败，返回截断提示")
                    interrupted_message = (
                        "抱歉，模型推理过程被中断，请重新提问。"
                        if self.is_chinese
                        else "Sorry, the model reasoning was interrupted. Please try again."
                    )
                    return AgentFinish(
                        return_values={"output": interrupted_message},
                        log=llm_output,
                    )

        # === 1. 检测 Action 格式 → 返回 AgentAction（继续调用工具）===
        action_key = None
        for key in ["\n 行动：", "\nAction:", "\n 行动:", "\n 行动："]:
            if key.strip() in llm_output:
                action_key = key.strip()
                break

        if action_key:
            parts = llm_output.split(action_key)
            if len(parts) >= 2:
                # 提取行动输入
                action_input_str = parts[1]

                # 尝试提取行动输入
                action_input_key = None
                for key in ["行动输入：", "Action Input:", "行动输入:", "Action Input："]:
                    if key in action_input_str:
                        action_input_key = key
                        break

                if action_input_key:
                    action = action_input_str.split(action_input_key)[0].strip()
                    action_input = action_input_str.split(action_input_key)[1].strip()

                    # 截断 JSON 后的多余文本（如 LLM 编造的"**查询结果**"等）
                    # 找到第一个完整 JSON 对象的结束位置
                    if action_input.startswith('{'):
                        brace_depth = 0
                        json_end = -1
                        for i, ch in enumerate(action_input):
                            if ch == '{':
                                brace_depth += 1
                            elif ch == '}':
                                brace_depth -= 1
                                if brace_depth == 0:
                                    json_end = i + 1
                                    break
                        if json_end > 0:
                            original_len = len(action_input)
                            action_input = action_input[:json_end]
                            if len(action_input) < original_len:
                                app_logger.info(f"\n截断 JSON 后的多余文本：{original_len} -> {len(action_input)}")

                    app_logger.info(f"\n检测到 Action: tool={action}")
                    app_logger.info(f"行动输入原始内容（前200字符）：{action_input[:200]}")
                    app_logger.info(f"返回 AgentAction，继续调用工具")
                    app_logger.info(f"{'='*60}")
                    app_logger.info(f"=== end parse (AgentAction) ===")
                    app_logger.info(f"{'='*60}\n")

                    # 解析行动输入为 JSON 或字典
                    try:
                        try:
                            action_input = json.loads(action_input)
                        except Exception:
                            try:
                                action_input = eval(action_input)
                            except Exception:
                                action_input = action_input.strip(" ").strip('"')

                        # 请求原文是查询范围的可信来源，不能让模型改写 gid 或 user_problem。
                        if isinstance(action_input, dict):
                            action_input = self._canonicalize_action_input(action_input, action)
                            app_logger.info(f"解析成功，参数 keys: {list(action_input.keys())}")
                        else:
                            app_logger.info(f"⚠️ 解析结果不是字典，类型: {type(action_input)}")

                        return AgentAction(
                            tool=action,
                            tool_input=action_input,
                            log=llm_output
                        )
                    except Exception as e:
                        app_logger.info(f"⚠️ 行动输入解析异常：{e}")
                        pass

        # === 2. 检测工具返回的 JSON（http_status 非 200）→ 兜底提示 ===
        llm_stripped = llm_output.strip()
        if llm_stripped.startswith('{'):
            try:
                data = json.loads(llm_stripped)
                if isinstance(data, dict) and 'http_status' in data:
                    http_status = data.get('http_status', 0)
                    app_logger.info(f"\n检测到 JSON 格式，http_status={http_status}")

                    # 状态码非 200，返回兜底提示
                    if http_status != 200:
                        app_logger.info(f"返回兜底提示 (http_status != 200)")
                        app_logger.info(f"{'='*60}")
                        app_logger.info(f"=== end parse (兜底提示) ===")
                        app_logger.info(f"{'='*60}\n")

                        if self.is_chinese:
                            fallback_message = (
                                    "抱歉，我暂时无法理解您的请求。建议您：\n\n"
                                    "1. **暴力破解查询**：'今天有哪些暴力破解攻击记录？'\n"
                                    "2. **账户安全查询**：'最近 7 天有没有异常的用户创建或删除操作？'\n"
                                    "3. **网络攻击查询**：'今天有没有检测到 IPS 入侵告警？'\n"
                                    "4. **系统安全查询**：'防火墙设备最近有没有异常重启记录？'\n"
                                    "5. **自由日志查询**：'查询今天 srcip=192.168.1.1 的所有日志'\n\n"
                                    "请尝试使用以上方式提问，我会更好地帮助您。"
                            )
                        else:
                            fallback_message = (
                                "Sorry, I could not understand the request. Please try one of these examples:\n\n"
                                "1. Brute-force attack query: 'What brute-force attacks occurred today?'\n"
                                "2. Account security query: 'Were there any unusual user creation or deletion events in the last 7 days?'\n"
                                "3. Network attack query: 'Were any IPS intrusion alerts detected today?'\n"
                                "4. System security query: 'Were there any unusual firewall reboot events recently?'\n"
                                "5. Free log query: 'Query all logs with srcip=192.168.1.1 today'\n\n"
                                "Please try again using one of these formats."
                            )

                        return AgentFinish(
                            return_values={"output": fallback_message},
                            log=llm_output,
                        )

                    # 状态码 200，返回 JSON（让 LLM 总结）
                    output_json = json.dumps(data, ensure_ascii=False)
                    app_logger.info(f"返回 JSON 数据 (http_status == 200)")
                    app_logger.info(f"output_json 长度：{len(output_json)}")
                    app_logger.info(f"{'='*60}")
                    app_logger.info(f"=== end parse (JSON) ===")
                    app_logger.info(f"{'='*60}\n")

                    return AgentFinish(
                        return_values={"output": output_json},
                        log=llm_output,
                    )
            except Exception as e:
                app_logger.info(f"JSON 解析失败：{e}")
                pass  # JSON 解析失败，落入兜底

        # === 3. 兜底：返回 LLM 输出或友好提示 ===
        # 尝试提取"最终答案："后的内容
        answer_match = re.search(r'(?:最终答案|Final Answer)\s*[:：]\s*(.+?)(?:\n|$)', llm_output, re.IGNORECASE | re.DOTALL)
        if answer_match:
            answer_text = answer_match.group(1).strip()
            app_logger.info(f"\n检测到'最终答案：'，长度={len(answer_text)}")
            app_logger.info(f"返回 AgentFinish (最终答案)")
            app_logger.info(f"{'='*60}")
            app_logger.info(f"=== end parse (最终答案) ===")
            app_logger.info(f"{'='*60}\n")

            return AgentFinish(
                return_values={"output": answer_text},
                log=llm_output,
            )

        # 【修复】提取"**查询结果**"后的内容作为最终答案
        # 当 LLM 输出包含"**查询结果**"时，说明已经是最终答案格式
        query_result_match = re.search(r'\*\*查询结果\*\*\s*(.+?)$', llm_output, re.DOTALL)
        if query_result_match:
            result_text = query_result_match.group(1).strip()
            app_logger.info(f"\n检测到'**查询结果**'，长度={len(result_text)}")
            app_logger.info(f"返回 AgentFinish (查询结果格式)")
            app_logger.info(f"{'='*60}")
            app_logger.info(f"=== end parse (查询结果) ===")
            app_logger.info(f"{'='*60}\n")

            return AgentFinish(
                return_values={"output": "**查询结果**\n" + result_text},
                log=llm_output,
            )

        # 【修复】不再将"思考："作为最终答案
        # "思考："是 ReAct 循环的中间步骤，不应该直接结束 Agent
        # 如果 LLM 只输出了"思考："而没有后续行动，说明需要继续生成
        # 让 Agent 继续迭代，而不是提前结束

        # 最终兜底：返回原始输出
        app_logger.info(f"\n最终兜底：返回原始输出")
        app_logger.info(f"{'='*60}")
        app_logger.info(f"=== end parse (兜底) ===")
        app_logger.info(f"{'='*60}\n")

        return AgentFinish(
            return_values={"output": llm_output.strip()},
            log=llm_output,
        )
