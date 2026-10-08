# SIEM Agent 接口文档

## 请求地址

| 环境 | 地址 |
|------|------|
| 生产环境 | `http://192.168.101.110:5050/agentchat` |
| 测试环境 | `http://10.180.158.23:5050/agentchat` |

## 请求方法

`POST`

## 请求参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `session_id` | string | 是 | 会话唯一标识，用于多轮对话上下文保持 |
| `request_id` | string | 否 | 单次请求唯一标识；不传时服务端自动生成，可用于追踪本次请求日志 |
| `user_input` | string | 是 | 用户输入的问题或指令 |

## 请求示例

```bash
curl -X POST http://192.168.101.110:5050/agentchat \
  -H "Content-Type: application/json" \
  -d '{"session_id": "session_001", "user_input": "查询最近 24 小时的登录失败记录"}'
```

## 响应结果

接口采用 **SSE (Server-Sent Events)** 流式响应，格式：`data: {JSON}\n\n`

| 事件类型 | 响应示例 | 说明 |
|---------|---------|------|
| `answer` | `{"answer": "<think>\n"}` / `{"answer": "正在处理工具结果..."}` / `{"answer": "工具及中间处理已完成。\n</think>\n"}` | 服务端统一管理的思考区域；普通中间状态和工具过程都位于同一个 `<think>...</think>` 区域，关闭事件不会只包含 `</think>` |
| `tools` | `{"tools": ["调用工具：xxx"]}` | 工具调用信息 |
| `final_answer` | `{"final_answer": "**查询结果**...", "is_final": true, "format": "markdown"}` | 清理思考标签后的正式答案；前端应按 Markdown 渲染并对最终答案区域加粗 |
| `error` | `{"error": "错误信息"}` | 错误信息 |

## 响应示例

```
data: {"answer": "<think>\n"}

data: {"answer": "分析用户问题并选择工具"}

data: {"tools": ["调用工具：free_query_request"]}

data: {"answer": "工具及中间处理已完成。\n</think>\n"}

data: {"final_answer": "**查询结果**\n\n- 总记录数：10 条\n- 关键发现：...", "is_final": true, "format": "markdown"}
```

> 兼容说明：服务端仍使用 `answer` 字段，但不会透传模型的原始长思考。前端遇到包含 `<think>` 的事件后进入思考区域，遇到包含 `</think>` 的事件后结束思考区域；所有 `tools` 事件都出现在关闭标签之前，收到 `final_answer` 后渲染正式答案。

暴力破解自动溯源完成后会发送独立的 `type=graph_data` 事件。`graphs` 最多包含累计覆盖率达到 80% 所需的前三个攻击源，顺序与文字报告完全一致；每个图包含 `ip`、`rank`、`brute_force_count`、`trace_event_count`、`time_window` 和仅用于绘图的 `graph_data.render_lines`。

每条 `render_line` 包含 `line_id`、`direction`、`count`、`status`、`event_role`、`steps`，并可包含 `first_seen`、`last_seen` 和 `details`。所有场景统一返回 `event_role=global_hit`，表示该线路来自指定 IP 和独立溯源时间窗口内的真实查询命中。前端应统一绘制全部 `render_lines`，不再使用暴力破解专用的 `detection_hit/trace_context` 区分。各检测场景的原始命中次数继续使用场景工具自身的统计字段（例如 `brute_force_count`），不由 `event_role` 表达。该图表达的是“Source IP Activity Trace / 关联活动溯源”。

---

*文档版本：v1.0*
