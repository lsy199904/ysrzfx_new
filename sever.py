"""
Agent 执行 → 触发回调 → 更新状态 → 放入队列 → 流式输出
"""
from __future__ import annotations
from uuid import UUID
from langchain.callbacks import AsyncIteratorCallbackHandler #导入异步迭代器回调处理器基类
import json
import asyncio
from typing import Any, Dict, List, Optional

from langchain.schema import AgentFinish, AgentAction
from langchain.schema.output import LLMResult


def dumps(obj: Dict) -> str:
    """
    简化 JSON 序列化操作
    """
    return json.dumps(obj, ensure_ascii=False)


class Status:
    start: int = 1
    running: int = 2
    complete: int = 3
    agent_action: int = 4
    agent_finish: int = 5
    error: int = 6
    tool_start: int = 7
    tool_finish: int = 8


class CustomAsyncIteratorCallbackHandler(AsyncIteratorCallbackHandler):
    """
    定义自定义异步迭代器回调处理器
    """
    def __init__(self): 
        #调用父类构造函数
        super().__init__()
        #创建异步队列
        self.queue = asyncio.Queue()#异步队列，用于存储事件数据，实现流式输出
        self.done = asyncio.Event()#异步事件，用于通知主循环异步迭代器完成/通知任务完成
        self.cur_tool = {}#当前工具信息字典
        self.out = True#初始化输出标志，用于控制是否输出当前工具调用信息
        self.collected_tokens = []  # 收集所有生成的 token
        self.has_output_final_answer = False  # 标记是否已输出过 final_answer
        self.task_ref = None  # 对 executor 协程的引用，用于 early stop 时取消任务
        self.agent_stop = False  # 兜底结果标识：探测失败时跳过后续 LLM 调用

    async def on_tool_start(self, serialized: Dict[str, Any], input_str: str, *, run_id: UUID,
                            parent_run_id: UUID | None = None, tags: List[str] | None = None,
                            metadata: Dict[str, Any] | None = None, **kwargs: Any) -> None:
        """
        定义工具开始时的回调方法
        """
        # 只在关键的语义边界截断，保留完整的JSON参数
        stop_words = ["Observation:", "Thought"]
        for stop_word in stop_words:
            index = input_str.find(stop_word)
            if index != -1:
                input_str = input_str[:index]
                break

        self.cur_tool = {
            "tool_name": serialized["name"],
            "input_str": input_str,
            "output_str": "",
            "status": Status.tool_start,
            "run_id": run_id.hex,
            "llm_token": "",
            "final_answer": "",
            "error": "",
            "graph_data": None,  # 【新增】图数据字段
        }
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_tool_end(self, output: str, *, run_id: UUID, parent_run_id: UUID | None = None,
                          tags: List[str] | None = None, **kwargs: Any) -> None:
        """
        定义工具结束时的回调方法
        """
        print(f"\n{'='*60}")
        print(f"=== on_tool_end DEBUG ===")
        print(f"{'='*60}")
        print(f"run_id: {run_id}")
        print(f"output 总长度：{len(output)}")
        print(f"\n【完整 output 内容】:")
        print(f"{output}")
        print(f"\n【END output】")
        
        # 尝试解析 JSON 并记录关键信息
        output_clean = output.replace("Answer:", "").strip()
        try:
            output_json = json.loads(output_clean)
            print(f"\nJSON 解析：成功")
            print(f"JSON keys: {list(output_json.keys())}")
        except json.JSONDecodeError as e:
            print(f"\nJSON 解析：失败 - {e}")
        
        # 【新增】检测兜底结果：如果工具返回了 __agent_stop__，直接终止后续 LLM 调用
        # 同时推送 tool_finish 和 agent_finish 两个事件给主循环处理
        try:
            result = json.loads(output_clean)
            print(f"=== early stop DEBUG ===")
            print(f"result.get('__agent_stop__'): {result.get('__agent_stop__')}")
            if result.get("__agent_stop__"):
                self.agent_stop = True
                steps = result.get("steps", [])
                suggestion = result.get("suggestion", result.get("error", "查询失败"))
                # 【修复】先定义 output_str，避免 NameError
                output_str = output.replace("Answer:", "").strip()
                self.cur_tool.update(
                    status=Status.tool_finish,
                    output_str=json.dumps(result, ensure_ascii=False),
                    output_length=len(output_str),
                )
                self.queue.put_nowait(dumps(self.cur_tool))
                # 创建独立的 agent_finish 事件字典，避免与 tool_finish 共用同一对象
                agent_finish_event = {
                    "status": Status.agent_finish,
                    "final_answer": suggestion,
                }
                if steps:
                    agent_finish_event["steps"] = steps
                self.queue.put_nowait(dumps(agent_finish_event))
                # 设置标志，防止 on_agent_finish 重复推送
                self.has_output_final_answer = True
                # 【关键修复】取消 executor 的 acall 协程，阻止后续 LLM 调用
                if self.task_ref is not None:
                    self.task_ref.cancel()
                    print("[on_tool_end] 已调用 task_ref.cancel() 取消 executor 协程")
                self.done.set()  # 终止后续处理
                print(f"final_answer (suggestion) 长度：{len(suggestion)}")
                print(f"final_answer 内容：{suggestion}")
                print(f"{'='*60}")
                print(f"=== end on_tool_end (early stop) ===")
                print(f"{'='*60}\n")
                return
            else:
                print(f"未检测到 __agent_stop__，继续正常流程")
                print(f"{'='*60}\n")
        except (json.JSONDecodeError, TypeError, NameError) as e:
            print(f"早期停止检测失败: {type(e).__name__}: {e}")
            print(f"output_clean 长度：{len(output_clean)}")
            print(f"output_clean 内容：{output_clean}")
            print(f"{'='*60}\n")
            pass

        print(f"{'='*60}")
        print(f"=== end on_tool_end ===")
        print(f"{'='*60}\n")
        
        self.out = True
        output_str = output.replace("Answer:", "")
        # 【新增】从工具返回中提取 trace_info（包含 graph_data 和完整溯源数据）
        trace_info = None
        graph_data = None
        try:
            output_json = json.loads(output_str.strip())
            trace_info = output_json.get("trace_info", {})
            
            # 优先从 trace_info 顶层提取 graph_data
            if isinstance(trace_info, dict) and trace_info.get("graph_data"):
                graph_data = trace_info.get("graph_data")
            # 兼容嵌套结构：从 ip_details[0].graph_data 提取
            elif isinstance(trace_info, dict) and trace_info.get("ip_details"):
                ip_details = trace_info.get("ip_details", [])
                if isinstance(ip_details, list) and len(ip_details) > 0:
                    first_detail = ip_details[0]
                    if isinstance(first_detail, dict) and first_detail.get("graph_data"):
                        graph_data = first_detail.get("graph_data")
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

        # 【新增】存储 trace_info 完整数据，供后续推送到前端
        cur_tool_data = {
            "status": Status.tool_finish,
            "output_str": output_str,
            "output_length": len(output_str),
            "graph_data": graph_data,
            "trace_info": trace_info,  # 存储完整的 trace_info（包含 ip_details 等）
        }

        # 【新增】只有当新提取到 graph_data 时才更新 graph_data，避免被 None 覆盖
        if graph_data or not self.cur_tool.get("graph_data"):
            cur_tool_data["graph_data"] = graph_data
        if trace_info:
            cur_tool_data["trace_info"] = trace_info

        self.cur_tool.update(cur_tool_data)
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_tool_error(self, error: Exception | KeyboardInterrupt, *, run_id: UUID,
                            parent_run_id: UUID | None = None, tags: List[str] | None = None, **kwargs: Any) -> None:
        self.cur_tool.update(
            status=Status.error,
            error=str(error),
        )
        """
        定义工具错误时的回调方法
        """
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """
        定义新 token 生成时的回调方法
        """
        # 如果已收到兜底结果，跳过后续 LLM token 输出
        if self.agent_stop:
            return
        # 【关键修复】如果已经输出过 final_answer，跳过后续的 token 输出
        if self.has_output_final_answer:
            return
            
        # 收集所有 token，用于诊断
        self.collected_tokens.append(token)
        
        # 打印每个 token，帮助诊断
        print(f"[on_llm_new_token] token={repr(token[:100] if len(token) > 100 else token)}")
        
        special_tokens = ["Action", "<|observation|>"]
        for stoken in special_tokens:
            if stoken in token:
                before_action = token.split(stoken)[0]#提取特殊词之前的内容
                self.cur_tool.update(
                    status=Status.running,
                    llm_token=before_action + "\n",
                )
                self.queue.put_nowait(dumps(self.cur_tool))
                self.out = False
                break

        if token and self.out:
            #更新当前工具信息
            self.cur_tool.update(
                #标记为运行中
                status=Status.running,
                llm_token=token,
            )
            self.queue.put_nowait(dumps(self.cur_tool))

    async def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """
        定义 LLM 开始生成时的回调方法
        """
        # 如果已收到兜底结果，跳过 LLM 调用
        if self.agent_stop:
            return
        #当 LLM 开始生成时触发
        self.cur_tool.update(
            status=Status.start,
            llm_token="",
        )
        self.queue.put_nowait(dumps(self.cur_tool))
    async def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        定义聊天模型开始时的回调方法
        """
        # 如果已收到兜底结果，跳过 chat model 调用
        if self.agent_stop:
            return
        self.cur_tool.update(
            status=Status.start,
            llm_token="",
        )
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """
        定义 LLM 生成完成时的回调方法
        """
        # 如果已收到兜底结果，跳过 LLM 结束通知
        if self.agent_stop:
            return
        print(f"\n{'='*60}")
        print(f"=== on_llm_end DEBUG ===")
        print(f"{'='*60}")
        
        # ========== Token 消耗监控 ==========
        llm_output = response.llm_output if hasattr(response, 'llm_output') and response.llm_output else {}
        if llm_output:
            print(f"\n【Token 使用统计】")
            token_usage = llm_output.get('token_usage', llm_output.get('usage', {}))
            if token_usage:
                prompt_tokens = token_usage.get('prompt_tokens', token_usage.get('input_tokens', 'N/A'))
                completion_tokens = token_usage.get('completion_tokens', token_usage.get('generated_tokens', 'N/A'))
                total_tokens = token_usage.get('total_tokens', 'N/A')
                print(f"  - 输入 Token (prompt_tokens): {prompt_tokens}")
                print(f"  - 输出 Token (completion_tokens): {completion_tokens}")
                print(f"  - 总计 Token (total_tokens): {total_tokens}")
                
                if isinstance(completion_tokens, int):
                    if completion_tokens >= 15000:
                        print(f"  ⚠️ 警告：输出 Token 数 ({completion_tokens}) 接近 max_tokens 限制 (16000)，可能导致截断！")
                    elif completion_tokens >= 10000:
                        print(f"  ⚠️ 注意：输出 Token 数 ({completion_tokens}) 较多")
            else:
                print(f"  - Token 使用信息：未找到 (llm_output keys: {list(llm_output.keys()) if isinstance(llm_output, dict) else 'N/A'})")
        else:
            print(f"\n【Token 使用统计】")
            print(f"  - llm_output 为空，无法获取 Token 使用信息")
        
        # ========== 诊断：检查收集的 token ==========
        print(f"\n【收集的 Token 诊断】")
        print(f"  - 收集的 token 数量：{len(self.collected_tokens)}")
        if self.collected_tokens:
            collected_text = ''.join(self.collected_tokens)
            print(f"  - 收集的 token 拼接长度：{len(collected_text)}")
            print(f"  - 收集的 token 内容预览 (前 500 字符):")
            print(f"    {collected_text[:500]}")
            if len(collected_text) > 500:
                print(f"    ... (还有 {len(collected_text) - 500} 字符)")
        else:
            print(f"  - 未收集到任何 token，说明 on_llm_new_token 从未被调用或 token 为空")
        
        # 记录 LLM 生成的完整响应
        full_text = ""
        if response.generations and len(response.generations) > 0:
            generation = response.generations[0]
            
            # 尝试多种方式提取文本
            if hasattr(generation, 'text') and generation.text:
                full_text = generation.text
            elif isinstance(generation, list) and len(generation) > 0:
                # generation 是列表，尝试提取第一个元素
                gen_item = generation[0] if len(generation) > 0 else None
                if hasattr(gen_item, 'text') and gen_item.text:
                    full_text = gen_item.text
                elif isinstance(gen_item, dict) and 'text' in gen_item:
                    full_text = gen_item['text']
            elif isinstance(generation, dict) and 'text' in generation:
                full_text = generation['text']
            
            if full_text:
                print(f"\nLLM 生成文本总长度：{len(full_text)}")
                
                # 检查是否包含思考标签
                has_thought_start = '<think>' in full_text
                has_thought_end = '</think>' in full_text
                print(f"  - 包含 <think> 标签：{has_thought_start}")
                print(f"  - 包含 </think> 标签：{has_thought_end}")
                
                if has_thought_start and not has_thought_end:
                    print(f"  ⚠️ 警告：发现未闭合的 <think> 标签，模型思考被截断！")
                
                print(f"\n【完整 LLM 输出内容】:")
                print(f"{full_text}")
                print(f"\n【END LLM 输出】")
            else:
                print("LLM 生成文本为空")
                print(f"  generation 类型：{type(generation)}")
                print(f"  response.generations 类型：{type(response.generations)}")
                print(f"  response.generations 内容：{response.generations}")
        else:
            print("LLM generations 为空")
            print(f"  response.generations: {response.generations}")
        
        # 重置收集的 token
        self.collected_tokens = []
        
        print(f"{'='*60}")
        print(f"=== end on_llm_end ===")
        print(f"{'='*60}\n")
        
        self.cur_tool.update(
            status=Status.complete,
            llm_token="\n",
        )
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_llm_error(self, error: Exception | KeyboardInterrupt, **kwargs: Any) -> None:
        """
        定义 LLM 错误时的回调方法
        """
        self.cur_tool.update(
            #标记为错误状态
            status=Status.error,
            error=str(error),
        )
        self.queue.put_nowait(dumps(self.cur_tool))

    async def on_agent_finish(
            self, finish: AgentFinish, *, run_id: UUID, parent_run_id: Optional[UUID] = None,
            tags: Optional[List[str]] = None,
            **kwargs: Any,
    ) -> None:
        """
        定义 Agent 完成时的回调方法
        """
        print(f"\n{'='*60}")
        print(f"=== on_agent_finish DEBUG ===")
        print(f"{'='*60}")
        print(f"run_id: {run_id}")
        
        final_answer = finish.return_values.get("output", "")
        # 如果是 __agent_stop__ JSON，提取纯文本 suggestion
        try:
            import json as json_mod
            parsed = json_mod.loads(final_answer)
            if isinstance(parsed, dict) and parsed.get("__agent_stop__"):
                original_answer = final_answer
                final_answer = parsed.get("suggestion") or parsed.get("error") or final_answer
                print(f"[on_agent_finish] 检测到 __agent_stop__ JSON，从 {len(original_answer)} 字符提取 suggestion: {len(final_answer)} 字符")
        except Exception:
            pass
        print(f"final_answer 总长度：{len(final_answer)}")
        print(f"\n【完整 final_answer 内容】:")
        print(f"{final_answer}")
        print(f"\n【END final_answer】")
        
        # 检查是否包含截断标记
        if final_answer.endswith("...") or final_answer.endswith("…"):
            print("⚠️ 警告：final_answer 可能已被截断（以...结尾）")
        
        # 检查是否包含预期的回复格式
        if "**查询结果**" in final_answer:
            print("✓ 包含预期的回复格式：**查询结果**")
        if "**关键发现**" in final_answer:
            print("✓ 包含预期的回复格式：**关键发现**")
        
        print(f"{'='*60}")
        print(f"=== end on_agent_finish ===")
        print(f"{'='*60}\n")
        
        # 【关键修复】只输出一次 final_answer
        print(f"has_output_final_answer: {self.has_output_final_answer}")
        print(f"final_answer 前100字符：{final_answer[:100]}")
        if not self.has_output_final_answer:
            self.has_output_final_answer = True
            print(f"✓ 推送 final_answer 到队列")
            # 返回最终答案
            cur_tool_data = {
                "status": Status.agent_finish,
                "final_answer": final_answer,
                "final_answer_length": len(final_answer),  # 额外记录长度
            }
            # 将 steps 信息也传递到 AgentFinish 的 return_values 中
            steps = finish.return_values.get("steps", [])
            if steps:
                cur_tool_data["steps"] = steps
            self.cur_tool.update(cur_tool_data)
            self.queue.put_nowait(dumps(self.cur_tool))
        self.cur_tool = {}