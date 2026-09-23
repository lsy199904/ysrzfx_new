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
| `answer` | `{"answer": "正在查询..."}` | AI 生成的文本片段 |
| `tools` | `{"tools": ["调用工具：xxx"]}` | 工具调用信息 |
| `final_answer` | `{"final_answer": "查询结果..."}` | 最终答案 |
| `error` | `{"error": "错误信息"}` | 错误信息 |

## 响应示例

```
data: {"answer": "正在为您查询..."}

data: {"tools": ["调用工具：free_query_request"]}

data: {"final_answer": "**查询结果**\n\n- 总记录数：10 条\n- 关键发现：..."}
```

---

*文档版本：v1.0*
