from __future__ import annotations
import json
from langchain.agents import Tool, AgentOutputParser
from langchain.prompts import StringPromptTemplate
from typing import List
from langchain.schema import AgentAction, AgentFinish
from pydantic.schema import model_schema


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
            thoughts += action.log
            thoughts += f"\nObservation: {observation}\nThought: "
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
        print(f"\n{'='*60}")
        print(f"=== CustomOutputParser.parse DEBUG ===")
        print(f"{'='*60}")
        print(f"llm_output 总长度：{len(llm_output)}")
        print(f"\n【完整 llm_output 内容】:")
        print(f"{llm_output}")
        print(f"\n【END llm_output】")

        # === 0. 清理 Qwen3 思考模式标签 ===
        # Qwen3 默认开启思考模式，生成 <think>...</think> 标签包裹的推理内容
        # 这些推理内容会干扰 ReAct 格式解析，需要提取 </think> 之后的有效内容
        if '</think>' in llm_output:
            llm_output = llm_output.split('</think>', 1)[1].strip()
            print(f"\n检测到 </think> 标签，提取 </think> 之后的内容")
            print(f"清理后 llm_output 长度：{len(llm_output)}")
            print(f"清理后内容：{llm_output}")
        elif '<think>' in llm_output or '<' + '' + 'tool_call>' in llm_output:
            # 只有 <think> 没有 </think>，说明思考内容被截断
            # 【修复】不再直接返回错误，而是尝试多种策略恢复 Action
            print(f"\n⚠️ 检测到未闭合的 <think> 标签（思考被截断），尝试恢复 Action/Answer")

            # 策略 A: 在 thinking 块中匹配"行动：xxx"或"Action: xxx"，思考中可能直接给出 Action
            inner_action_match = re.search(
                r'(?:行动|Action)\s*[：:]\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                llm_output,
                re.IGNORECASE
            )

            # 策略 B: 在 thinking 块中匹配"我应该使用 xxx 工具" / "调用 xxx" 等自然语言 Action
            natural_action_match = re.search(
                r'(?:我应该使用|调用|使用|选择)\s*([a-zA-Z_][a-zA-Z0-9_]*)',
                llm_output
            )

            recovered_action = None
            if inner_action_match:
                recovered_action = inner_action_match.group(1).strip()
                print(f"策略 A 命中 - 从 thinking 块提取 Action: {recovered_action}")
            elif natural_action_match:
                candidate = natural_action_match.group(1).strip()
                # 验证是否是已知工具名（包含 _request 或常见关键字）
                if '_request' in candidate or candidate in ['tool', 'search', 'query']:
                    recovered_action = candidate
                    print(f"策略 B 命中 - 从自然语言提取 Action: {recovered_action}")

            if recovered_action:
                # 重构为标准 ReAct 格式，强制工具名+空参数（让 Agent 重新生成参数）
                llm_output = f"行动：{recovered_action}\n行动输入：{{}}"
                print(f"重构为标准格式: {llm_output[:200]}")
            else:
                # 策略 C: 取 <think> 之后的内容
                after_think = llm_output.split('<think>', 1)[-1].strip()
                if after_think and '<think>' not in after_think and len(after_think) > 5:
                    llm_output = after_think
                    print(f"策略 C 命中 - 提取 <think> 之后的内容，长度：{len(llm_output)}")
                else:
                    # 完全无法提取任何内容
                    print(f"所有策略均失败，返回截断提示")
                    return AgentFinish(
                        return_values={"output": "抱歉，模型推理过程被中断，请重新提问。"},
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
                                print(f"\n截断 JSON 后的多余文本：{original_len} -> {len(action_input)}")

                    print(f"\n检测到 Action: tool={action}")
                    print(f"行动输入原始内容（前200字符）：{action_input[:200]}")
                    print(f"返回 AgentAction，继续调用工具")
                    print(f"{'='*60}")
                    print(f"=== end parse (AgentAction) ===")
                    print(f"{'='*60}\n")

                    # 解析行动输入为 JSON 或字典
                    try:
                        try:
                            action_input = json.loads(action_input)
                        except Exception:
                            try:
                                action_input = eval(action_input)
                            except Exception:
                                action_input = action_input.strip(" ").strip('"')

                        # 验证解析结果：如果是字典，检查关键字段是否存在
                        if isinstance(action_input, dict):
                            print(f"解析成功，参数 keys: {list(action_input.keys())}")
                        else:
                            print(f"⚠️ 解析结果不是字典，类型: {type(action_input)}")

                        return AgentAction(
                            tool=action,
                            tool_input=action_input,
                            log=llm_output
                        )
                    except Exception as e:
                        print(f"⚠️ 行动输入解析异常：{e}")
                        pass

        # === 2. 检测工具返回的 JSON（http_status 非 200）→ 兜底提示 ===
        llm_stripped = llm_output.strip()
        if llm_stripped.startswith('{'):
            try:
                data = json.loads(llm_stripped)
                if isinstance(data, dict) and 'http_status' in data:
                    http_status = data.get('http_status', 0)
                    print(f"\n检测到 JSON 格式，http_status={http_status}")

                    # 状态码非 200，返回兜底提示
                    if http_status != 200:
                        print(f"返回兜底提示 (http_status != 200)")
                        print(f"{'='*60}")
                        print(f"=== end parse (兜底提示) ===")
                        print(f"{'='*60}\n")

                        return AgentFinish(
                            return_values={
                                "output": (
                                    "抱歉，我暂时无法理解您的请求。建议您：\n\n"
                                    "1. **暴力破解查询**：'今天有哪些暴力破解攻击记录？'\n"
                                    "2. **账户安全查询**：'最近 7 天有没有异常的用户创建或删除操作？'\n"
                                    "3. **网络攻击查询**：'今天有没有检测到 IPS 入侵告警？'\n"
                                    "4. **系统安全查询**：'防火墙设备最近有没有异常重启记录？'\n"
                                    "5. **自由日志查询**：'查询今天 srcip=192.168.1.1 的所有日志'\n\n"
                                    "请尝试使用以上方式提问，我会更好地帮助您。"
                                )
                            },
                            log=llm_output,
                        )

                    # 状态码 200，返回 JSON（让 LLM 总结）
                    output_json = json.dumps(data, ensure_ascii=False)
                    print(f"返回 JSON 数据 (http_status == 200)")
                    print(f"output_json 长度：{len(output_json)}")
                    print(f"{'='*60}")
                    print(f"=== end parse (JSON) ===")
                    print(f"{'='*60}\n")

                    return AgentFinish(
                        return_values={"output": output_json},
                        log=llm_output,
                    )
            except Exception as e:
                print(f"JSON 解析失败：{e}")
                pass  # JSON 解析失败，落入兜底

        # === 3. 兜底：返回 LLM 输出或友好提示 ===
        # 尝试提取"最终答案："后的内容
        answer_match = re.search(r'最终答案：\s*(.+?)(?:\n|$)', llm_output, re.DOTALL)
        if answer_match:
            answer_text = answer_match.group(1).strip()
            print(f"\n检测到'最终答案：'，长度={len(answer_text)}")
            print(f"返回 AgentFinish (最终答案)")
            print(f"{'='*60}")
            print(f"=== end parse (最终答案) ===")
            print(f"{'='*60}\n")

            return AgentFinish(
                return_values={"output": answer_text},
                log=llm_output,
            )

        # 【修复】提取"**查询结果**"后的内容作为最终答案
        # 当 LLM 输出包含"**查询结果**"时，说明已经是最终答案格式
        query_result_match = re.search(r'\*\*查询结果\*\*\s*(.+?)$', llm_output, re.DOTALL)
        if query_result_match:
            result_text = query_result_match.group(1).strip()
            print(f"\n检测到'**查询结果**'，长度={len(result_text)}")
            print(f"返回 AgentFinish (查询结果格式)")
            print(f"{'='*60}")
            print(f"=== end parse (查询结果) ===")
            print(f"{'='*60}\n")

            return AgentFinish(
                return_values={"output": "**查询结果**\n" + result_text},
                log=llm_output,
            )

        # 【修复】不再将"思考："作为最终答案
        # "思考："是 ReAct 循环的中间步骤，不应该直接结束 Agent
        # 如果 LLM 只输出了"思考："而没有后续行动，说明需要继续生成
        # 让 Agent 继续迭代，而不是提前结束

        # 最终兜底：返回原始输出
        print(f"\n最终兜底：返回原始输出")
        print(f"{'='*60}")
        print(f"=== end parse (兜底) ===")
        print(f"{'='*60}\n")

        return AgentFinish(
            return_values={"output": llm_output.strip()},
            log=llm_output,
        )
