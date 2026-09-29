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
| `answer` | `{"answer": "<think>"}` / `{"answer": "分析用户问题"}` / `{"answer": "</think>"}` | 思考过程增量；开始和结束使用 `<think>` / `</think>` 标记 |
| `tools` | `{"tools": ["调用工具：xxx"]}` | 工具调用信息 |
| `final_answer` | `{"final_answer": "**查询结果**...", "is_final": true, "format": "markdown"}` | 清理思考标签后的正式答案；前端应按 Markdown 渲染并对最终答案区域加粗 |
| `error` | `{"error": "错误信息"}` | 错误信息 |

## 响应示例

```
data: {"answer": "<think>"}

data: {"answer": "分析用户问题并选择工具"}

data: {"answer": "</think>"}

data: {"tools": ["调用工具：free_query_request"]}

data: {"final_answer": "**查询结果**\n\n- 总记录数：10 条\n- 关键发现：...", "is_final": true, "format": "markdown"}
```

> 兼容说明：服务端仍使用 `answer` 字段，但只发送经过边界标记的思考内容，不发送未经处理的 Action/Observation。前端遇到 `<think>` 后进入思考区域，遇到 `</think>` 后结束思考区域；收到 `final_answer` 后渲染正式答案。

图谱事件中的 `graph_data` 继续保留原有 `nodes`、`edges`、`stats` 字段，并新增 `render_lines`。`render_lines` 是供双通道/时序线路图使用的聚合路径，包含 `line_id`、`direction`、`count`、`status`、`steps`，下行流量线路可能额外包含 `details.destination_ip` 和 `details.destination_port`。

---

*文档版本：v1.0*
