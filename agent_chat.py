# -*- coding: utf-8 -*-
"""
实现了一个基于 LangChain + FastAPI 的智能 Agent 服务，主要特点：

ReAct 模式：思考 → 行动 → 观察循环
实例隔离：每个请求独立的工具和会话
流式响应：SSE 实时推送
多轮对话：滑动窗口记忆
错误处理：自动处理解析错误

"""
import asyncio
import json
import logging
import sys
import copy 
import hashlib
import re
import uuid
import ipaddress
from pathlib import Path
from typing import Awaitable
from stream_formatter import (
    ThoughtStreamParser,
    clean_final_answer,
    contains_cjk,
    detect_response_language,
    split_thoughts,
    thought_event_to_answer,
)
from fastapi.middleware.cors import CORSMiddleware

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from utils.redis_manager import get_redis_manager, init_redis_manager
from contextlib import asynccontextmanager
from tools.index_config import INDEX_SOURCE_PATTERN
from config import (
    APP_HOST,
    APP_LOG_LEVEL,
    APP_PORT,
    APP_TIMEOUT_KEEP_ALIVE,
    CORS_ORIGINS,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_ENABLE_THINKING,
    LLM_MAX_CONTEXT_TOKENS,
    LLM_MAX_OUTPUT_TOKENS,
    LLM_MIN_OUTPUT_TOKENS,
    LLM_CALL_TIMEOUT,
    LLM_MODEL,
    LLM_SAFETY_MARGIN,
    LLM_TEMPERATURE,
)

# Final answers and tool-selection actions do not need a large completion
# budget. A hard cap also leaves room for large but compacted observations.
AGENT_OUTPUT_TOKEN_CAP = 12000

# ========================================
# 日志配置：使用 QueueHandler + QueueListener 确保并发安全
# ========================================
import os
# 强制使用北京时间
os.environ['TZ'] = 'Asia/Shanghai'
try:
    import time
    time.tzset()
except (ImportError, AttributeError):
    pass  # 某些环境不支持 tzset

import queue  # noqa: E402

_log_queue = queue.Queue(-1)  # 无界队列

app_logger = logging.getLogger("agent_chat")
app_logger.setLevel(logging.INFO)
# 添加队列处理器
_queue_handler = logging.handlers.QueueHandler(_log_queue)
app_logger.addHandler(_queue_handler)

# 全局唯一的 QueueListener（由主线程运行）
_listener = logging.handlers.QueueListener(
    _log_queue,
    logging.FileHandler("agent_chat.log", encoding="utf-8", mode="a"),
    logging.StreamHandler(sys.stdout),
    respect_handler_level=True,
)
_listener.start()
LOG_FILE_PATH = str(
    Path(__file__).resolve().parent / "agent_chat.log"
)

async def get_redis_manager_instance():
    """获取 Redis 管理器实例（已在 lifespan 中初始化）"""
    return get_redis_manager()

async def get_session_history(session_id: str) -> list:
    """从 Redis 获取会话历史"""
    try:
        mgr = get_redis_manager()
        return await mgr.get_session(session_id)
    except Exception as e:
        app_logger.warning(f"获取会话失败：{session_id}, error: {e}")
    return []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理：启动时初始化 Redis，关闭时清理"""
    # 启动时初始化
    await init_redis_manager()
    yield
    # 关闭时清理
    mgr = get_redis_manager()
    await mgr.close()


app = FastAPI(title="Chat Agent 接口", lifespan=lifespan)
app.add_middleware(
            CORSMiddleware,
            allow_origins=CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            )


# ========================================
# 场景提示词配置
# ========================================
# 按场景组织提示词，每个场景可包含：
#   system_prompt: 系统级角色设定（告知 LLM 身份和能力）
#   format_prompt: ReAct 格式模板（控制工具调用流程）
# 新增场景时，在此字典中添加新的 key-value 即可
prompts = {
    # 通用兜底提示词
    "default": {
        "system_prompt": "你是一个乐于助人的安全助手。",
        "format_prompt": (
            '【输出格式硬性要求】先使用 <think>...</think> 标签输出思考过程，然后直接按指定格式输出。\n'
            '【重要】必须先输出 <antThinking> 标签开始思考，思考完毕后用 </antThinking> 结束思考，然后给出行动。\n'
            '你可以使用以下工具：\n\n'
            '{tools}\n\n'
            '请按以下格式回复：\n'
            '问题：需要回答的输入问题\n'
            '思考：应该如何思考以及使用哪些工具\n'
            '行动：应该采取的行动，从[{tool_names}] 中选择的一个，如果你判断不涉及工具调用直接回答即可\n'
            '行动输入：行动的输入参数\n\n'
            '问题：{input}\n\n'
            '思考：{agent_scratchpad}\n\n'
        ),
    },
    "auto_select": {
        "system_prompt": (
            "你是一位智能的网络安全分析助手，能够根据用户问题自动选择合适的工具进行分析。"
            "【语言要求】根据用户问题的语言自动选择回复语言：如果用户用中文提问，用中文回答；如果用户用英文提问，用英文回答。"
            "你可以根据问题的语义和意图，自主选择最适合的工具来回答用户的问题。"
            "【重要】如果问题是通用问答、自我介绍、闲聊等不需要查询日志的情况，直接回答即可，无需调用工具！"
            "【重要】收到工具返回结果后，直接归纳总结并输出最终答案，禁止再次调用工具！"
        ),
        "format_prompt": (
            "【输出格式硬性要求】先使用 <think>...</think> 标签输出思考过程，然后按指定格式输出。"
            "你必须：1）用 <think> 标签包裹思考过程；2）思考后输出行动。"
            "你是一位智能的网络安全分析助手，可以根据用户问题自主选择工具。"
            "【重要说明】如果问题是通用问答、自我介绍、闲聊等不需要查询日志的情况，直接输出最终答案，无需调用工具！"
            "【语言要求】根据用户问题的语言自动选择回复语言：如果用户用中文提问，用中文回答；如果用户用英文提问，用英文回答。思考过程和最终答案必须使用与用户问题相同的语言！"
            "【可用工具说明】\n"
            "{tools}\n\n"
            "【工具选择指南】\n"
            "- brute_force_request: 当用户询问暴力破解攻击等问题时使用\n"
            "- account_security_monitor_request: 当用户询问账户安全、用户创建/删除、权限变更等问题时使用\n"
            "- network_attack_request: 当用户询问网络攻击、IPS 入侵检测、攻击行为等问题时使用\n"
            "- system_security_request: 当用户询问系统安全、设备重启/关机、配置变更等问题时使用\n"
            "- alert_rule_request: 当用户询问告警规则、告警分析等问题时使用\n"
            "- ip_trace_request: 当用户询问某 IP 的完整攻击链路、溯源分析、攻击时间线等问题时使用\n"
            "- free_query_request: 当用户自由查询日志、搜索特定记录、自定义条件查询时使用\n\n"
            "【free_query_request 专用规则】\n"
            "当选择 free_query_request 时，如果生成的PPL调用状态码返回200就不要继续调用了，只有不是200才继续调用，ppl_query 参数的生成规则如下：\n"
            f"1. PPL 必须以 `search source=`{INDEX_SOURCE_PATTERN}`` 或 `search source={INDEX_SOURCE_PATTERN}` 开头\n"
            "2. 时间过滤使用 @timestamp 字段，格式：@timestamp >= 'YYYY-MM-DD HH:MM:SS'\n"
            "3. IP 过滤使用 srcip、dstip、remip 等字段\n"
            "4. 用户过滤使用 user 字段\n"
            "5. 设备组过滤使用 @gid 字段，格式：@gid = '设备组 ID'\n"
            "6. 使用 fields 指定需要的返回字段\n"
            "7. 使用 sort 排序结果\n"
            "8. 使用 stats 进行聚合统计\n"
            "【常见日志类型和字段】\n"
            "- 登录日志：subtype='system'/'vpn', action='login'/'logout', status='failed'/'success'\n"
            "- 账户操作：action='Add'/'Delete', cfgpath='user.local'\n"
            "- IPS 告警：type='utm', subtype='ips', level='alert'\n"
            "- 系统事件：subtype='system', logdesc='Device rebooted'/'Device shutdown'\n"
            "- 通用字段：@timestamp, srcip, dstip, user, action, msg, @gid, devname, policyid\n\n"
            "【其他几个场景工具参数提取规则】\n"
            "- start_time: 从用户问题中提取开始时间。如果用户提到相对时间（如'今天'、'最近 24 小时'、'近 7 天'、'近 30 天'等），直接传递原始文本（如'今天'、'最近 24 小时'、'近 7 天'），工具会自动解析为精确时间。如果是具体日期，填'YYYY-MM-DD'格式。如果用户问题中没有提到时间，填 None\n"
            "- end_time: 从用户问题中提取结束时间。如果用户提到相对时间（如'今天'、'最近 24 小时'、'近 7 天'、'近 30 天'等），直接传递原始文本（如'今天'、'最近 24 小时'、'近 7 天'），工具会自动解析为精确时间。如果是具体日期，填'YYYY-MM-DD'格式。如果用户问题中没有提到时间，填 None\n"
            "- 【示例】用户问'最近 24 小时的登录失败记录'，start_time 填'最近 24 小时'，end_time 填'最近 24 小时'，工具会解析为当前时间减 24 小时到当前时间\n"
            "- filter_ip: 只有用户明确提到具体 IP 地址时才填 IP，否则填 None\n"
            "- filter_user: 只有用户明确提到用户名时才填用户名，否则填 None\n"
            "- aggregate: 仅当用户明确问'哪个最多/排名第一/top 1/排名'时填 True，否则填 False\n"
            "- group_by: 仅在 aggregate=True 时使用，默认'srcip'\n"
            "- gid: 可选，设备组 ID，当用户明确提到特定设备组或防火墙设备时才传入 gid 参数；必须逐字复制用户原文中的数字，不得删减或改写（例如 19936 不能写成 1936）\n"
            "- user_problem: 必须逐字复制用户问题原文，不能改写、摘要、补充或省略任何数字\n\n"
            "【防幻觉规则 - 最重要】\n"
            "- 【关键】所有统计数字必须来自工具返回的 ip_summary/ip_stats 或 compression.summary_text，绝不从 data_sample 推断数字；自动溯源场景优先使用 trace_info.trace_ip_stats。\n"
            "- 【关键】工具返回的 data_sample 只是原始数据样本，不代表全部记录；Top 3、总 IP 数、次数和占比必须使用 ip_summary/ip_stats。若存在 trace_info.trace_ips，则它是文字报告与 graph_data.graphs 的共同权威列表，按该顺序展示，累计覆盖率提前停止时不足 3 个不得补齐。\n"
            "- 【关键】时间线只能列出工具明确返回的 trace_info.trace_ips（没有该字段时才使用统计 Top 3）攻击源 IP（不足 3 个就显示有几个就显示几个，不要凑数）。对于未在工具数据中出现的 IP、时间戳、用户名，禁止在时间线中凭空生成！\n"
            "- 【关键】如果工具返回的是聚合统计（例如 54 个 IP 共 1864 条），不要逐个列出 54 个 IP；只列 Top 3（按攻击次数），其余写 另有 X 个 IP 详见原始记录\n"
            "- 【关键】IP 总数必须等于工具返回的 ip_summary.unique_ip_count（或 ip_count/unique_ips 字段）。如工具返回 unique_ip_count=3，答案里写 3 个 IP 详情 + 0 个其他 IP；如工具返回 unique_ip_count=59，则 Top 3 + 另有 56 个 IP 详见原始记录。**严禁编造或推断 IP 总数**\n"
            "- 【关键】工具未在 ip_stats/ip_summary/top_ip_records 中返回的 IP，禁止出现在最终答案的任何位置（包括 Top 3、剩余 IP、时间线）\n"
            "- 【关键】时间线时间戳精度按工具数据自适应：工具返回原始日志含精确时间戳（HH:MM:SS）时，直接用 [HH:MM:SS] 格式（如 [00:00:57]）；工具仅返回时段（例如 00:00 到 11:09）时，用约 HH:MM 表达；严禁编造任何工具未给出的具体秒数\n"
            "- 【关键】禁止使用示例数据或假设数据来填充回复格式\n"
            "- 【关键】你必须基于当前工具返回的数据生成答案，不能参考历史对话中的任何数据\n"
            "- 【关键】如果当前工具返回 count=0 或 data=[]，必须回答 未查询到相关数据，不要编造统计信息\n"
            "\n"
            "【历史数据语境感知】\n"
            "- 【关键】检测查询的时间范围与今天的关系：\n"
            "  - 查询的是过去 7 天内的数据：使用 近期威胁 话术，建议侧重实时防御与短期措施\n"
            "  - 查询的是 7 天前或数月前的数据：使用 历史复盘 话术，建议侧重溯源、复盘、制度加固，禁止使用 立即封禁 IP / 强制改密码 / 启用账户锁定 等运维指令\n"
            "  - 查询的是未来日期：按用户输入理解，不要质疑日期合理性\n"
            "- 历史复盘场景的措辞示例：该事件发生于 X 月 X 日，建议作为案例复盘并完善防御规则，而不是立即在防火墙封禁\n"
            "\n"
            "【其他规则】\n"
            "- 【关键】只调用一次工具！收到 HTTP 200 工具返回后，必须直接归纳总结生成最终答案，禁止再次调用工具，也禁止重新查询缓存！\n"
            "- 【关键】free_query_request 例外：只有当 PPL 查询返回错误（状态码非 200）时才需要重新生成 PPL 再次查询\n"
            "- 【关键】brute_force_request、account_security_monitor_request、network_attack_request、system_security_request、alert_rule_request 这些工具调用一次后必须直接输出答案！\n"
            "- 【关键】如果工具返回状态码200的情况下 count=0 或 data=[]（无数据），直接按照回复格式生成最终答案说明无数据，禁止再次调用工具！\n"
            "- 【输出要求】不要输出任何解释性文字，直接输出最终答案！\n"
            "\n"
            "【禁止行为】\n"
            "- 禁止直接复制工具返回的 JSON 数据\n"
            "- 禁止输出原始数据结构\n"
            "- 禁止在时间线中编造工具未返回的 IP、时间戳、用户名\n"
            "\n"
            "【必须行为】\n"
            "- 必须用自然语言总结工具结果\n"
            "- 必须输出用户可读的最终答案\n"
            "\n"
            "【回复格式说明 - 统一使用四段式 Markdown 大纲】\n\n"
            "1. 当需要调用工具时，按以下格式输出：\n"
            "   如果用户用中文提问：\n"
            "     问题：{input}\n"
            "     思考：分析用户问题意图，选择合适的工具\n"
            "     行动：选择的工具名称\n"
            "     行动输入：{{\"user_problem\": \"...\", \"start_time\": \"...\", \"end_time\": \"...\", \"filter_ip\": \"...\", \"filter_user\": \"...\", \"aggregate\": true/false, \"group_by\": \"...\", \"gid\": \"...\"}}\n\n"
            "   【严禁】在输出行动和行动输入之后，不得继续输出任何查询结果、统计数据或最终答案！\n"
            "   【严禁】不得在工具返回数据之前编造或预测查询结果！\n"
            "   必须等待工具返回真实数据后，才能生成最终答案！\n\n"
            "2. 当收到工具返回后，按以下统一的四段式 Markdown 大纲输出最终答案（不要再次输出 问题/思考/行动/行动输入）：\n"
            "   【格式硬性要求】\n"
            "   - 必须按 ## 1 → ## 2 → ## 3 → ## 4 顺序输出，缺一段即为输出不完整\n"
            "   - 仅在工具数据支持时填写具体数字；工具未给出的字段写 未提供 或留空\n"
            "   - 时间线只展示与 graph_data.graphs 完全相同的 trace_info.trace_ips（不足 3个就显示有几个就显示几个，不要凑数），剩余写 另有 X 个 IP，详见原始记录\n"
            "   - 中文用户：使用中文小标题；英文用户：使用 English headers\n\n"
            "   【硬性输出要求】\n"
            "   - 工具返回 Observation 后，最终答案部分以 ## 1. 事件概述 开头\n"
            "   - ## 1. 之前禁止出现好的/接下来/用户的问题/根据回复格式要求等元思考\n"
            "   - 不要复述 prompt 已写明的格式说明\n"
            "   - 工具返回内容已包含在 Observation 中，不要再总结工具结果\n"
            "   - 4 段必须全部输出完毕，不得在中途停止\n\n"
            "   ## 1. 事件概述\n"
            "   - 时间范围：工具返回数据的时间段（YYYY-MM-DD HH:MM ~ HH:MM）\n"
            "   - 事件类型：暴力破解 / 账户变更 / 网络攻击 / 系统事件 / 告警分析 / 自由查询\n"
            "   - 总记录数：X 条（如有原始/压缩双数字，标注 原始 X 条，压缩后 Y 条）\n"
            "   - MITRE ATT&CK 技术（仅攻击类）：如 T1110（暴力破解）、T1110.001（密码猜测）、T1078（有效账户）等；无对应技术时写 无明确映射\n"
            "   - 风险等级：高 / 中 / 低 / 无，并附 1 句依据\n\n"
            "   ## 2. 关键实体\n"
            "   - 攻击源 Top 3（优先列 `trace_info.trace_ips`，必须与 graph_data.graphs 的 IP 和顺序完全一致；不足 3 个就显示有几个就显示几个）：\\n"\
            "     - **重要：优先使用 `trace_info.trace_ip_stats` 的 `count` 和 `percentage`；没有时再使用 `ip_stats` 中对应 IP 的预计算字段，禁止 LLM 自行计算！**\\n"\
            "     - <IP>：<内网IP/公网IP>，攻击 X 次（占比 Y%），主要行为：<工具返回的具体描述>\n"
            "     - ...\n"
            "   - 目标对象：涉及设备（devname）、目标用户（user Top 3）、目标端口/协议、命中策略 ID（policyid Top 3）\n"
            "   - 账户影响：被锁定的账户（account_locked）、密码错误次数最多的账户、是否存在成功登录\n"
            "   - 综合分析：一句话定性攻击性质（如：内网主机被感染后横向爆破 / 公网 IP 自动化撞库 / 历史攻击复盘等）\n\n"
            "   ## 3. 攻击详细时间线TOP3\n"
            "   每个 IP 一段，必须先收集该 IP 的所有事件并严格按每条日志的 `@timestamp` 升序排列后再输出。时间顺序是唯一的排列依据；‘首次探测’、‘首次尝试’、‘批量爆破’、‘最终结果’只允许作为事件标签，绝不能为了凑成固定四阶段而重排真实时间。时间戳格式：工具返回精确时间戳时用 [HH:MM:SS]，仅有时段时用 约 HH:MM。\n"
            "   - 首次尝试必须取该攻击源最早的认证/登录事件；首次探测必须取真实最早的探测/网络攻击事件；批量爆破使用相关事件最早到最晚时间；最终结果使用该攻击源最后一条相关事件时间。所有时间必须来自结构化日志的 `@timestamp`，禁止根据事件名称猜测。\n"
            "   - 如果首次探测晚于首次尝试，必须按真实时间顺序展示，不得强行调整阶段顺序或生成虚假时间。\n"
            "   **重要：文字报告中的攻击源列表必须与 `trace_info.trace_ips` 和 `graph_data.graphs` 完全一致；次数和占比优先使用 `trace_info.trace_ip_stats` 的预计算字段，禁止 LLM 自行计算！**\\n"\
            "   攻击源：<IP>（X 次，占 Y%）\n"
            "   - 只有日志中确实存在最早的探测事件时，才标记【首次探测】；之后发生的探测必须按原时间位置标记【后续探测】，不得移到时间线开头。\n"
            "   - 只有日志中确实存在最早的尝试/登录事件时，才标记【首次尝试】；后续尝试继续按时间顺序输出。\n"
            "   - 连续或批量事件可以标记【批量爆破】，但该标签不能改变事件在时间线中的位置。\n"
            "   - 只有日志明确表明攻击在所查询窗口内结束，才标记【最终结果】；较早发生的锁定、拦截或中间状态只能标记【阶段结果】，不能称为最终结果。\n"
            "   - 禁止补造工具未返回的阶段、事件、IP、用户或时间；缺失阶段直接省略，不要强制输出四个阶段。\n"
            "   剩余 IP：另有 X 个攻击源 IP 因篇幅省略，详见原始记录。\n\n"
            "   ## 4. 安全建议（按历史/近期语境区分）\n"
            "   - 历史复盘场景（查询日期距今超过 7 天）：\n"
            "     - 溯源复盘：拉取相关时间段全量日志进行 IOC 关联分析\n"
            "     - 制度加固：完善账户锁定策略、密码复杂度、最小权限\n"
            "     - 规则完善：基于该事件特征更新 IPS/WAF 规则\n"
            "     - 账户巡检：复核受影响账户当前状态，必要时强制改密\n"
            "   - 近期威胁场景（查询日期在 7 天内）：\n"
            "     - 短期：封禁高频攻击源 IP、强制改密高危账户、启用账户锁定\n"
            "     - 长期：部署 IPS 自动拦截、MFA、异常登录监控\n"
            "   - 无数据场景：当前时间范围内未发现异常，建议确认日志覆盖范围\n\n"
            "3. 如果是通用问答不需要工具，直接输出答案即可\n\n"
            "问题：{input}\n\n"
            "思考：{agent_scratchpad}\n\n"
        ),
    },
    # English requests use a separate prompt instead of appending an English
    # sentence to the legacy Chinese template.  This prevents Chinese
    # examples and headings from steering the model back to Chinese.
    "auto_select_en": {
        "system_prompt": (
            "You are a network-security analysis assistant. "
            "Use the original user request as the only source for language and query scope. "
            "After one successful tool call, produce the complete report without calling another tool."
        ),
        "format_prompt": (
            "ENGLISH-ONLY REQUEST CONTRACT.\n"
            "The user request is in English. Use English for every natural-language token in this prompt's output: "
            "thought/action text, tool status, errors, headings, and final_answer. "
            "Do not output Chinese characters. Do not copy language style from logs, history, tool output, or examples.\n"
            "Keep tool names, JSON keys, PPL, field names, IP addresses, timestamps, and raw log values unchanged.\n"
            "Use one tool at most. When a tool returns HTTP 200, summarize that result directly and do not call another tool. "
            "If the result has no records, state that clearly. Never invent counts, IPs, users, timestamps, or attack types.\n\n"
            "Available tools:\n{tools}\n\n"
            "Tool selection:\n"
            "- brute_force_request: failed-login and brute-force records\n"
            "- account_security_monitor_request: account and permission changes\n"
            "- network_attack_request: IPS/network attacks\n"
            "- system_security_request: system and device events\n"
            "- alert_rule_request: alert-rule analysis\n"
            "- ip_trace_request: activity trace for a specified source IP\n"
            "- free_query_request: custom log/PPL queries\n\n"
            "Action input rules:\n"
            "- Copy user_problem exactly from the original request. Never rewrite or truncate numbers such as gid 19936.\n"
            "- Copy explicit gid, IP, user, and date values exactly. Use None only when the user did not provide a value.\n"
            "- For a concrete date use YYYY-MM-DD; for a relative range pass the original relative wording.\n"
            "- Use aggregate=true only when the user explicitly asks for ranking/statistics.\n\n"
            "Before a tool call emit only a concise English action block:\n"
            "Question: {input}\n"
            "Thought: Select the appropriate security tool.\n"
            "Action: one tool name\n"
            "Action Input: {{\"user_problem\": \"...\", \"start_time\": \"...\", \"end_time\": \"...\", \"filter_ip\": null, \"filter_user\": null, \"aggregate\": false, \"group_by\": \"srcip\", \"gid\": \"...\"}}\n\n"
            "Do not predict tool results before the tool returns.\n"
            "After the tool result, output a complete Markdown report with exactly these headings:\n"
            "## 1. Event Summary\n"
            "## 2. Key Entities\n"
            "## 3. Top 3 Detailed Attack Timelines\n"
            "## 4. Security Recommendations\n"
            "For automatic tracing, sources must come from trace_info.trace_ips and trace_info.trace_ip_stats in the exact order used by graph_data.graphs; show fewer when the 80% threshold stops early. Otherwise use the tool's complete ip_stats/ip_summary. "
            "Do not rank from data samples. Sort timeline events by structured @timestamp ascending and preserve real order. "
            "Use only stages supported by logs; never invent a stage or timestamp.\n\n"
            "Question: {input}\n"
            "Thought: {agent_scratchpad}\n"
        ),
    },
}



# 全局会话存储（内存缓存，同时同步到 Redis）
user_sessions = {}
session_lock = asyncio.Lock()

# Token 估算函数 - 从 log_compressor 导入
from utils.log_compressor import LogCompressor

def _estimate_tokens(text: str) -> int:
    """
    估算文本的 Token 数量（使用 log_compressor 中的 LogCompressor）
    """
    compressor = LogCompressor()
    return compressor.estimate_tokens(text)


async def wrap_done(fn: Awaitable, event: asyncio.Event):
    """
    Wrap an awaitable with a event to signal when it's done or an exception is raised.
    定义异步函数，包装可等待对象
    """
    try:
        await fn
    except asyncio.CancelledError:
        # early stop 时主动取消 executor 协程，记录日志后正常退出
        app_logger.info("wrap_done: executor task was cancelled (early stop)")
    except Exception as e:
        app_logger.exception(e)
        msg = f"Caught exception: {e}"
        app_logger.error(f'{e.__class__.__name__}: {msg}',)
    finally:
        # Signal the aiter to stop.
        event.set() #通知等待该事件的其他协程，任务已完成


@app.post("/agentchat")
async def chat_agent_stream(request: Request):
    from langchain.agents import LLMSingleActionAgent
    from tools.tool_base import EarlyStopAgentExecutor
    from langchain.chains import LLMChain
    from langchain.memory import ConversationBufferWindowMemory #滑动窗口记忆，用于保存最近N轮对话
    #from langchain_openai import ChatOpenAI #用于调用大语言模型
    from langchain_community.chat_models import ChatOpenAI
    from sse_starlette import EventSourceResponse #用于实现服务器推送事件（流式响应）

    from custom_template import CustomPromptTemplate, CustomOutputParser#导入自定义提示词模板和解析器
    from tools_select import tools, tool_names, TOOL_TO_SCENE

    from sever import CustomAsyncIteratorCallbackHandler, Status

    data = await request.json()
    session_id = data.get('session_id')
    user_input = data.get('user_input')
    request_id = str(data.get('request_id') or uuid.uuid4().hex)
    login_account = data.get('login_account', '')
    is_admin = bool(data.get('is_admin', False))
    allowed_gids = data.get('allowed_gids', None)
    # Freeze the response language from the original request before any
    # history, tool result, or model output is observed.
    response_language = detect_response_language(user_input)
    is_chinese_input = response_language == "zh"

    # ========================================
    # 请求日志
    # ========================================
    app_logger.info(f"\n{'='*60}")
    app_logger.info(f"【请求开始】request_id: {request_id}, session_id: {session_id}, user_input: {user_input}")
    app_logger.info(f"  login_account: {login_account}, is_admin: {is_admin}, allowed_gids: {allowed_gids}")
    app_logger.info(f"{'='*60}\n")

    # 【数据权限】参数校验：
    # 1. login_account 必传，缺失直接拒绝请求（防止未鉴权调用拿到全量数据）
    # 2. 非 admin 用户必须携带非空 allowed_gids 白名单
    # 3. admin 用户忽略 allowed_gids，不注入任何过滤
    if not login_account:
        app_logger.warning(f"[响应] HTTP 403 | 缺少 login_account | request_id: {request_id}, session_id: {session_id}")
        return JSONResponse(
            status_code=403,
            content={"error": (
                "请求缺少登录账号信息，无法确认您的数据权限，请退出后重新登录再试。"
                if is_chinese_input
                else "The request is missing login-account information, so data access cannot be verified. Please sign in again."
            )},
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    # 白名单归一化为字符串列表；admin 默认不限制，但如果传入了 allowed_gids 也用于索引探测/效率优化
    if is_admin:
        # 管理员如果有 allowed_gids，用于索引探测和查询优化（仅提高效率，不影响权限）
        normalized_gids = [str(g).strip() for g in (allowed_gids or []) if str(g).strip()] if allowed_gids else None
    else:
        normalized_gids = [str(g).strip() for g in (allowed_gids or []) if str(g).strip()]
        if not normalized_gids:
            app_logger.warning(f"[响应] HTTP 403 | 缺少 allowed_gids | request_id: {request_id}, session_id: {session_id}, login_account: {login_account}")
            return JSONResponse(
                status_code=403,
                content={"error": (
                    "请求未携带用户组权限信息（allowed_gids），无法确认您的数据权限，请退出后重新登录再试。"
                    if is_chinese_input
                    else "The request is missing allowed_gids, so data access cannot be verified. Please sign in again."
                )},
                headers={"Content-Type": "application/json; charset=utf-8"}
            )

    # 【数据权限】注入 request_ctx（LLM 不可见、不可伪造）
    # is_admin=True -> allowed_gids=None（不限制）；否则为白名单列表
    from tools.tool_base import request_ctx
    request_ctx.set({
        "login_account": login_account,
        "is_admin": is_admin,
        "allowed_gids": normalized_gids,
        "request_id": request_id,
        "response_language": response_language,
    })

    # 校验必要参数
    if not session_id or not user_input:
        app_logger.warning(f"[响应] HTTP 400 | 缺少 session_id 或 user_input | request_id: {request_id}, session_id: {session_id}, user_input: {user_input}")
        return JSONResponse(
            status_code=400,
            content={"error": (
                "session_id和user_input为必填参数"
                if is_chinese_input
                else "session_id and user_input are required."
            )},
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    # Redis 和进程内会话均按账号隔离，避免不同用户复用同一个 session_id 串读历史。
    scoped_session_id = hashlib.sha256(
        f"{login_account}\0{session_id}".encode("utf-8")
    ).hexdigest()

    # 请求级日志与会话历史分层保存：会话继续承载多轮上下文，请求记录按 request_id 单独追踪。
    try:
        mgr = await get_redis_manager_instance()
        await mgr.save_request_log(
            scoped_session_id,
            request_id,
            {
                "request_id": request_id,
                "session_id": session_id,
                "login_account": login_account,
                "status": "started",
                "user_input": user_input,
                "is_admin": is_admin,
                "allowed_gids": normalized_gids,
            },
        )
    except Exception as e:
        app_logger.warning(f"保存请求开始日志失败：request_id={request_id}, error: {e}")

    # English prose must remain English, while raw log values (for example a
    # Chinese device/user name) are allowed to stay unchanged.  Register only
    # values from raw record/graph sections, never backend steps or messages.
    allowed_raw_cjk_literals = set()

    def _contains_cjk(text: str) -> bool:
        return contains_cjk(text)

    def _collect_raw_cjk_literals(value) -> None:
        if isinstance(value, dict):
            for child in value.values():
                _collect_raw_cjk_literals(child)
            return
        if isinstance(value, list):
            for child in value:
                _collect_raw_cjk_literals(child)
            return
        if not isinstance(value, str) or not _contains_cjk(value):
            return
        stripped = value.strip()
        if stripped[:1] in {"{", "["}:
            try:
                _collect_raw_cjk_literals(json.loads(stripped))
                return
            except (TypeError, json.JSONDecodeError):
                pass
        if stripped:
            allowed_raw_cjk_literals.add(stripped)
        allowed_raw_cjk_literals.update(
            segment for segment in re.findall(r"[\u4e00-\u9fff]+", stripped)
            if segment
        )

    def _register_allowed_raw_values(tool_output: dict) -> None:
        if not isinstance(tool_output, dict):
            return
        _collect_raw_cjk_literals(tool_output.get("data"))
        trace_info = tool_output.get("trace_info")
        if not isinstance(trace_info, dict):
            return
        _collect_raw_cjk_literals(trace_info.get("graph_data"))
        for detail in trace_info.get("ip_details", []):
            if not isinstance(detail, dict):
                continue
            _collect_raw_cjk_literals(detail.get("activities"))
            _collect_raw_cjk_literals(detail.get("graph_data"))

    def _language_fallback(kind: str = "error") -> str:
        if is_chinese_input:
            return {
                "thought": "正在处理工具结果...",
                "tool": "已收到工具结果。",
                "final": "查询已完成，但服务未能生成符合中文要求的完整报告，请稍后重试。",
                "error": "工具返回了无法直接展示的结果。",
            }.get(kind, "正在处理请求...")
        return {
            "thought": "Processing the tool result...",
            "tool": "The tool returned a structured result.",
            "final": "The query completed, but the service could not generate a complete English report. Please try again.",
            "error": "The tool returned a result that cannot be displayed directly.",
        }.get(kind, "Processing the request...")

    def _safe_intermediate_text(value: str) -> str:
        """Never expose a model thought in the wrong request language."""
        text = str(value or "")
        if not text:
            return ""
        # Model-generated reasoning is intentionally not forwarded verbatim.
        # A short server-owned status keeps the single think region useful
        # without leaking a wrong-language chain of thought.
        return _language_fallback("thought")

    def _localize_tool_text(value: str) -> str:
        """Translate fixed tool labels while preserving technical values."""
        text = str(value or "")
        if not text or not _contains_cjk(text):
            return text

        # Structured step details are generated by the tools themselves.  Map
        # only stable labels; the captures keep index patterns, gid values,
        # timestamps, PPL, IPs, and raw field values unchanged.
        text = re.sub(
            r"原始记录\s*(\d+)\s*条，压缩后\s*(\d+)\s*条",
            r"Original \1 records, compressed to \2 records",
            text,
        )
        text = re.sub(
            r"查询完成，共\s*(\d+)\s*条记录",
            r"Query Complete, Total \1 records",
            text,
        )
        text = re.sub(
            r"共查询到\s*(\d+)\s*条记录",
            r"Total \1 records found",
            text,
        )

        replacements = (
            ("查询流程展示", "Query Flow"),
            ("索引存在性探测", "Index Existence Check"),
            ("解析用户问题", "Parse User Question"),
            ("构建 PPL 查询", "Build PPL Query"),
            ("执行 API 查询", "Execute API Query"),
            ("返回结果", "Return Results"),
            ("探测索引模式：", "Index pattern: "),
            ("探测用户组：", "User groups: "),
            ("探测结果：存在", "Result: exists"),
            ("探测结果：不存在", "Result: not found"),
            ("工具执行完成", "Tool execution completed"),
            ("工具执行失败", "Tool execution failed"),
            ("错误信息", "Error"),
            ("查询失败", "Query failed"),
            ("查询时间：未指定", "Query Time: Not specified"),
            ("IP 过滤：无", "IP Filter: None"),
            ("用户过滤：无", "User Filter: None"),
        )
        for source, target in replacements:
            text = text.replace(source, target)

        # If an unfamiliar backend sentence remains, suppress that prose
        # rather than leaking Chinese into an English SSE stream.
        return text if not _contains_cjk(text) else _language_fallback("tool")

    def _safe_tools_payload(payload: dict) -> dict:
        """Keep technical PPL/code intact, but suppress wrong-language prose."""
        if is_chinese_input or not isinstance(payload, dict):
            return payload
        items = payload.get("tools")
        if not isinstance(items, list):
            return payload
        safe_items = []
        for item in items:
            text = str(item or "")
            if not _contains_cjk(text):
                safe_items.append(item)
            elif "search source=" in text or "```" in text:
                # PPL and code are technical payloads; preserve them verbatim.
                safe_items.append(item)
            else:
                safe_items.append(_localize_tool_text(text))
        result = dict(payload)
        result["tools"] = safe_items
        return result

    def _final_language_ok(value: str) -> bool:
        text = str(value or "")
        if not text:
            return False
        if is_chinese_input:
            english_headings = (
                "## 1. Event Summary",
                "## 2. Key Entities",
                "## 3. Attack Timeline",
                "## 4. Security Recommendations",
            )
            return _contains_cjk(text) and not any(marker in text for marker in english_headings)
        chinese_headings = (
            "## 1. 事件概述",
            "## 2. 关键实体",
            "## 3. 攻击详细时间线",
            "## 4. 安全建议",
        )
        if any(marker in text for marker in chinese_headings):
            return False
        prose = text
        for literal in sorted(allowed_raw_cjk_literals, key=len, reverse=True):
            prose = prose.replace(literal, "")
        return not _contains_cjk(prose)

    def _safe_final_text(value: str) -> str:
        text = clean_final_answer(str(value or "")).strip()
        return text if _final_language_ok(text) else _language_fallback("final")

    def _localized_fixed_error(value: str, tool_output: dict | None = None) -> str:
        """Localize deterministic permission/index errors without another LLM call."""
        text = str(value or "")
        if _final_language_ok(text):
            return text
        status = tool_output.get("http_status") if isinstance(tool_output, dict) else None
        gid_match = re.search(r"(?:gid|user\s*group|用户组)\s*[:=]?\s*([0-9]+)", text, re.IGNORECASE)
        gid = gid_match.group(1) if gid_match else "the requested user group"
        if status == 403:
            return (
                f"抱歉，您当前没有用户组 {gid} 的查询权限。"
                if is_chinese_input
                else f"Access denied: you do not have permission to query user group {gid}."
            )
        if status == 404:
            return (
                f"用户组 {gid} 的日志索引不存在，无法查询。"
                if is_chinese_input
                else f"The log index for user group {gid} does not exist, so the query cannot be completed."
            )
        return text

    def _structured_report_fallback(tool_output: dict | None, tool_name: str = "") -> str:
        """Build a grounded four-part report when the final LLM pass fails."""
        result = tool_output if isinstance(tool_output, dict) else {}
        event_types = {
            "brute_force_request": ("暴力破解", "brute-force activity"),
            "network_attack_request": ("网络攻击", "network-attack activity"),
            "account_security_monitor_request": ("账户安全事件", "account-security activity"),
            "system_security_request": ("系统安全事件", "system-security activity"),
            "alert_rule_request": ("告警规则分析", "alert-rule analysis"),
            "free_query_request": ("安全日志查询", "security-log query"),
            "ip_trace_request": ("IP 关联活动溯源", "IP activity trace"),
        }
        event_type_zh, event_type_en = event_types.get(
            str(tool_name or ""),
            ("安全日志查询", "security-log query"),
        )
        try:
            count = int(result.get("count", 0) or 0)
        except (TypeError, ValueError):
            count = 0
        data = result.get("data") if isinstance(result.get("data"), list) else []
        stats = result.get("ip_stats") if isinstance(result.get("ip_stats"), list) else []
        if not stats:
            counts = {}
            for record in data:
                if not isinstance(record, dict):
                    continue
                ip = record.get("attack_src") or record.get("source.ip")
                if ip:
                    counts[str(ip)] = counts.get(str(ip), 0) + 1
            total = sum(counts.values())
            stats = [
                {
                    "ip": ip,
                    "count": value,
                    "percentage": round(value * 100 / total, 1) if total else 0.0,
                }
                for ip, value in sorted(counts.items(), key=lambda item: item[1], reverse=True)
            ]
        all_stats = [item for item in stats if isinstance(item, dict) and item.get("ip")]
        compression = result.get("compression") if isinstance(result.get("compression"), dict) else {}
        original_count = compression.get("original_count", count)
        compressed_count = compression.get("compressed_count")
        if compressed_count is not None and compressed_count != original_count:
            count_text_zh = f"原始 {original_count} 条，压缩后 {compressed_count} 条"
            count_text_en = f"Original {original_count} records, compressed to {compressed_count} records"
        else:
            count_text_zh = f"{count} 条"
            count_text_en = f"{count} records"

        def ip_kind(value: str) -> str:
            try:
                return "private" if ipaddress.ip_address(value).is_private else "public"
            except ValueError:
                return "unknown"

        trace_info = result.get("trace_info") if isinstance(result.get("trace_info"), dict) else {}
        # Automatic brute-force tracing may stop after one or two IPs once the
        # 80% coverage threshold is reached.  Its trace_ips list is therefore
        # authoritative for both the report and graph_data.graphs; do not
        # refill the report from the full ip_stats list.
        selected_ips = [
            str(ip) for ip in trace_info.get("trace_ips", [])
            if ip not in (None, "")
        ]
        selected_stats = trace_info.get("trace_ip_stats")
        if selected_ips:
            stats_by_ip = {
                str(item.get("ip")): item
                for item in all_stats
            }
            selected_stats_by_ip = {
                str(item.get("ip")): item
                for item in (selected_stats if isinstance(selected_stats, list) else [])
                if isinstance(item, dict) and item.get("ip")
            }
            ordered_stats = []
            total_count = sum(
                int(item.get("count", 0) or 0)
                for item in all_stats
            )
            for ip in selected_ips:
                item = dict(selected_stats_by_ip.get(ip) or stats_by_ip.get(ip) or {"ip": ip})
                item["ip"] = ip
                try:
                    item["count"] = int(item.get("count", 0) or 0)
                except (TypeError, ValueError):
                    item["count"] = 0
                if "percentage" not in item:
                    item["percentage"] = round(
                        item["count"] * 100 / total_count, 1
                    ) if total_count else 0.0
                ordered_stats.append(item)
            stats = ordered_stats
        else:
            # Non-tracing tools retain their historical Top 3 behavior.
            stats = all_stats
        top_stats = [item for item in stats[:3] if isinstance(item, dict) and item.get("ip")]
        details = trace_info.get("ip_details") if isinstance(trace_info.get("ip_details"), list) else []
        details_by_ip = {
            item.get("ip"): item for item in details
            if isinstance(item, dict) and item.get("ip")
        }
        if is_chinese_input:
            lines = [
                "## 1. 事件概述",
                f"- 查询状态：{'成功' if result.get('http_status') == 200 else '失败'}",
                f"- 命中记录数：{count_text_zh}",
                f"- 攻击源数量：{len(all_stats)} 个",
                f"- 事件类型：{event_type_zh}（以工具返回结果为准）",
                "",
                "## 2. 关键实体",
                "- 攻击源 Top 3：",
            ]
            if top_stats:
                for item in top_stats:
                    lines.append(
                        f"  - {item['ip']}：{item.get('count', 0)} 次，"
                        f"占比 {item.get('percentage', 0)}%，{('内网' if ip_kind(str(item['ip'])) == 'private' else '公网')} IP"
                    )
            else:
                lines.append("  - 未返回攻击源统计。")
            lines.extend([
                "- 目标对象：工具未返回的字段不作推断。",
                "- 账户影响：工具未返回的字段不作推断。",
                "",
                "## 3. 攻击详细时间线TOP3",
            ])
            for item in top_stats:
                detail = details_by_ip.get(item.get("ip"), {})
                lines.append(
                    f"- 攻击源：{item['ip']}（{item.get('count', 0)} 次，占比 {item.get('percentage', 0)}%）"
                )
                graph = detail.get("graph_data") if isinstance(detail, dict) else {}
                render_lines = graph.get("render_lines", []) if isinstance(graph, dict) else []
                if render_lines:
                    lines.append(f"  - 关联活动线路：{len(render_lines)} 条。")
                else:
                    lines.append("  - 未返回该 IP 的时间线线路。")
            if not top_stats:
                lines.append("- 未返回可用的攻击时间线。")
            lines.extend([
                "",
                "## 4. 安全建议（按历史/近期语境区分）",
                "- 建议依据工具返回的真实记录继续复核相关日志；未返回的事实不作补充。",
            ])
            return "\n".join(lines)

        lines = [
            "## 1. Event Summary",
            f"- Query status: {'successful' if result.get('http_status') == 200 else 'failed'}",
            f"- Matching records: {count_text_en}",
            f"- Attack-source count: {len(all_stats)}",
            f"- Event type: {event_type_en}, based only on the tool result.",
            "",
            "## 2. Key Entities",
            "- Top 3 attack sources:",
        ]
        if top_stats:
            for item in top_stats:
                lines.append(
                    f"  - {item['ip']}: {item.get('count', 0)} events, "
                    f"{item.get('percentage', 0)}%, {ip_kind(str(item['ip']))} IP"
                )
        else:
            lines.append("  - No attack-source statistics were returned.")
        lines.extend([
            "- Targets: fields not returned by the tool are not inferred.",
            "- Account impact: fields not returned by the tool are not inferred.",
            "",
            "## 3. Top 3 Detailed Attack Timelines",
        ])
        for item in top_stats:
            detail = details_by_ip.get(item.get("ip"), {})
            lines.append(
                f"- Source IP: {item['ip']} ({item.get('count', 0)} events, {item.get('percentage', 0)}%)"
            )
            graph = detail.get("graph_data") if isinstance(detail, dict) else {}
            render_lines = graph.get("render_lines", []) if isinstance(graph, dict) else []
            lines.append(
                f"  - Related activity lines: {len(render_lines)}."
                if render_lines else "  - No timeline lines were returned for this IP."
            )
        if not top_stats:
            lines.append("- No usable attack timeline was returned.")
        lines.extend([
            "",
            "## 4. Security Recommendations",
            "- Review the real records returned by the tool; do not infer facts that were not returned.",
        ])
        return "\n".join(lines)

    def _is_incomplete_agent_answer(text: str) -> bool:
        normalized = re.sub(r"\s+", " ", str(text or "")).strip().lower()
        if normalized in {
            "agent stopped due to iteration limit or time limit.",
            "agent stopped due to iteration limit or time limit",
            "agent stopped due to iteration limit",
            "agent stopped due to time limit",
        }:
            return True
        if str(text or "").lstrip().startswith("{"):
            try:
                parsed = json.loads(text)
                return isinstance(parsed, dict) and "http_status" in parsed
            except (TypeError, json.JSONDecodeError):
                return False
        return False

    def _deterministic_final_fallback(
        tool_output: dict | None = None,
        tool_name: str = "",
    ) -> str:
        """Return a language-safe answer without another model call.

        A successful tool result must still produce a grounded report when the
        final agent pass is truncated or times out.  Error/suggestion payloads
        are localized separately so permission and index failures remain
        useful instead of becoming a generic iteration-limit message.
        """
        result = tool_output if isinstance(tool_output, dict) else {}
        if result.get("http_status") == 200:
            report = _structured_report_fallback(result, tool_name=tool_name)
            if report and _final_language_ok(report):
                return report

        candidate = result.get("suggestion") or result.get("error") or ""
        localized = _localized_fixed_error(candidate, result)
        if localized and _final_language_ok(localized):
            return localized
        return _language_fallback("final")

    def _get_language_strings(is_chinese: bool) -> dict:
        """
        根据语言返回对应的字符串
        """
        if is_chinese:
            return {
                "query_flow": "查询流程展示",
                "step_prefix": "步骤",
                "query_complete": "查询完成，共",
                "records_suffix": "条记录",
                "query_failed": "查询失败，HTTP 状态码：",
                "tool_executed": "工具执行完成",
                "tool_executed_failed": "工具执行失败",
                "error_msg": "错误信息",
                "unknown_error": "未知错误",
                "parse_failed": "解析失败",
                "start_exec_tool": "开始执行工具...",
                "call_tool": "调用工具",
                "final_answer": "最终答案"
            }
        else:
            return {
                "query_flow": "Query Flow",
                "step_prefix": "Step",
                "query_complete": "Query Complete, Total ",
                "records_suffix": " records",
                "query_failed": "Query Failed, HTTP Status:",
                "tool_executed": "Tool Executed",
                "tool_executed_failed": "Tool Execution Failed",
                "error_msg": "Error Message",
                "unknown_error": "Unknown Error",
                "parse_failed": "Parse Failed",
                "start_exec_tool": "Starting tool execution...",
                "call_tool": "Calling Tool",
                "final_answer": "Final Answer"
            }

    def _build_language_instruction(is_chinese: bool) -> str:
        """Build a request-scoped language contract for every model-visible output."""
        if is_chinese:
            return (
                "\n\n【本次请求语言契约】\n"
                "用户使用中文提问。所有面向用户的内容都必须使用中文，包括思考字段、工具状态、错误信息和最终答案。\n"
                "保留工具名、JSON 键名、字段名、PPL、IP、时间戳和原始日志值，不要翻译这些技术值。\n"
                "不要因为工具返回英文或历史记录使用英文而切换语言。\n"
                "最终答案必须是完整中文 Markdown 报告，并严格保留已确认的四段式标题，不得改名：‘## 1. 事件概述’、‘## 2. 关键实体’、‘## 3. 攻击详细时间线TOP3’、‘## 4. 安全建议（按历史/近期语境区分）’。\n"
                "自动溯源时，关键实体和时间线必须严格使用 trace_info.trace_ips / trace_info.trace_ip_stats，并与 graph_data.graphs 的 IP 和顺序完全一致；累计覆盖率提前停止时不足 3 个不得补齐。没有 trace_ips 时才使用工具统计 Top 3。\n"
                "所有中间内容都属于同一个 <think> 区域，工具完成后才能结束思考并输出 final_answer。\n"
            )
        return (
            "\n\n[REQUEST LANGUAGE CONTRACT - HIGHEST PRIORITY]\n"
            "The user is asking in English. Every user-visible response MUST be in English, including "
            "Thought/Action text, tool status, step titles/details, errors, suggestions, and final_answer.\n"
            "Do not output Chinese characters in any user-facing prose. Ignore Chinese examples in this prompt; "
            "they are documentation only.\n"
            "Keep tool names, JSON keys, field names, PPL, IP addresses, timestamps, and raw log values unchanged.\n"
            "The final answer must be a complete English Markdown report with headings such as ## 1. Query Summary, ## 2. Key Entities, ## 3. Attack Timeline, and ## 4. Recommendations.\n"
            "For automatic tracing, list only trace_info.trace_ips / trace_info.trace_ip_stats in the exact graph_data.graphs order; if cumulative coverage stops at one or two IPs, do not refill to three. Without trace_ips, use the actual Top 3 tool statistics.\n"
            "All intermediate content belongs to one <think> region; close it only after every tool call and intermediate result is complete, then emit final_answer.\n"
            "After receiving a tool result, produce the final answer in English only. Do not call another tool "
            "when the result already has HTTP status 200.\n"
            "For every attack timeline, sort all events by their actual @timestamp in ascending order before writing. "
            "Use the earliest authentication event for First Attempt, the earliest real probe/network-attack event for First Probe, "
            "the earliest and latest timestamps of related events for Brute Force, and the last related event for Final Result. "
            "All times must come from structured @timestamp fields; never infer time from event names. "
            "If the first probe occurs after the first attempt, preserve that real order and do not invent or reorder stages. "
            "Stage labels such as First Probe, First Attempt, Brute Force, Stage Result, and Final Result are annotations only and must never reorder events. "
            "Use Subsequent Probe for later probes, use Stage Result for an earlier lock/block/interception, and use Final Result only when the logs prove the attack ended in the queried window. "
            "Omit unsupported stages instead of inventing them.\n"
            "For the final answer, use English Markdown headings such as:\n"
            "## 1. Event Summary\n## 2. Key Entities\n## 3. Attack Timeline\n## 4. Security Recommendations\n"
        )

    def _build_recovery_report_template(is_chinese: bool) -> str:
        """Return the confirmed detailed report template for recovery generation."""
        if is_chinese:
            return (
                "严格按以下已确认模板输出，不得更换标题或删除内部条目：\n"
                "## 1. 事件概述\n"
                "- 时间范围：使用工具返回的真实时间范围\n"
                "- 事件类型：暴力破解 / 账户变更 / 网络攻击 / 系统事件 / 告警分析 / 自由查询\n"
                "- 总记录数：使用工具真实 count；如有压缩信息，写明原始数量和压缩后数量\n"
                "- MITRE ATT&CK 技术：仅在工具数据支持时填写，否则写无明确映射\n"
                "- 风险等级：高 / 中 / 低 / 无，并给出基于工具数据的依据\n\n"
                "## 2. 关键实体\n"
                "- 攻击源 Top N：自动溯源时按 trace_info.trace_ips / trace_ip_stats 顺序输出并与 graph_data.graphs 完全一致；累计覆盖率提前停止时 N 可为 1 到 3，不得从完整 ip_stats 补齐。每个 IP 展示次数、占比、内网/公网类型和工具支持的主要行为\n"
                "- 目标对象：涉及设备、目标用户 Top 3、目标端口/协议、命中策略 ID Top 3\n"
                "- 账户影响：账户锁定、密码错误高频账户、是否存在成功登录\n"
                "- 综合分析：仅基于工具结果定性攻击性质\n\n"
                "## 3. 攻击详细时间线TOP3\n"
                "- 仅展示 trace_info.trace_ips 中实际选中的 1 到 3 个攻击源；每个 IP 只使用该 IP 的真实事件\n"
                "- 所有事件按结构化 @timestamp 升序排列，时间来自日志，不得猜测\n"
                "- 首次探测、首次尝试、批量爆破、阶段结果、最终结果只在日志支持时出现，不得强行补齐或重排\n"
                "- 最后按工具真实 IP 总数说明剩余 IP 数量，不得推断或虚构\n\n"
                "## 4. 安全建议（按历史/近期语境区分）\n"
                "- 历史复盘：溯源复盘、制度加固、规则完善、账户巡检\n"
                "- 近期威胁：短期处置和长期防护\n"
                "- 无数据：明确说明未查询到相关数据，并建议确认日志覆盖范围\n"
            )
        return (
            "Use the confirmed detailed template below without renaming headings or deleting items:\n"
            "## 1. Event Summary\n"
            "- Time range, event type, verified record count, supported MITRE ATT&CK mapping, and evidence-based risk level\n\n"
            "## 2. Key Entities\n"
            "- Top N Attack Sources: for automatic tracing use trace_info.trace_ips / trace_ip_stats in the exact graph_data.graphs order; N may be 1 to 3 when cumulative coverage stops early. Show count, percentage, private/public type, and supported behavior\n"
            "- Targets: devices, Top 3 users, ports/protocols, and Top 3 policy IDs\n"
            "- Account impact and a tool-supported overall assessment\n\n"
            "## 3. Top 3 Detailed Attack Timelines\n"
            "- Use only real events for each IP and sort by structured @timestamp ascending\n"
            "- Do not invent or reorder First Probe, First Attempt, Brute Force, Stage Result, or Final Result labels\n\n"
            "## 4. Security Recommendations\n"
            "- Distinguish historical review, recent threat response, and no-data cases\n"
        )

    # Shared only by the two nested generators for this one HTTP request.
    # It lets the outer SSE normalizer build a grounded final fallback if the
    # inner generator terminates before emitting its own final event.
    stream_state = {
        "latest_tool_output": None,
        "latest_tool_name": "",
    }
    
    async def agent_chat_iterator(user_input: str, session_id: str, request_id: str):
        """
        这是流式响应的核心生成器
        """
        # 1. 实例化当前请求独立的回调函数（无共享状态）
        callback = CustomAsyncIteratorCallbackHandler(request_id=request_id)
        
        # 2. Use the language frozen at request entry.  Never re-detect from
        # history, tool output, PPL, or model-generated text.
        is_chinese_input = response_language == "zh"
        str_lang = _get_language_strings(is_chinese_input)

        # 2. 工具实例隔离：为当前请求创建独立工具副本（避免全局工具共享冲突）
        # 深拷贝全局tools，确保每个请求的工具状态独立，并提取工具名
        local_tools = [copy.deepcopy(tool) for tool in tools]
        local_tool_names = [tool.name for tool in local_tools]  # 独立的工具名列表
        
        # 使用 auto_select 场景，让大模型根据工具描述自主选择
        scene = "auto_select" if is_chinese_input else "auto_select_en"
        # One tool call followed by the executor's generated final pass.
        # This prevents repeated queries and keeps the report grounded in the
        # first complete observation.
        max_iterations = 1

        # 3. 初始化 Prompt 模板：英文请求使用完全独立的英文模板，避免
        # 中文示例、中文标题和中文工具描述进入模型上下文。
        prompt_template = (
            prompts[scene]["format_prompt"]
            + _build_language_instruction(is_chinese_input)
        )
        prompt_template_agent = CustomPromptTemplate(
            template=prompt_template,
            tools=local_tools,  # 替换为局部工具
            input_variables=["input", "intermediate_steps", "history"],
            language=response_language,
        )

        # 4. 会话内存隔离：使用 Redis 加载历史对话
        async with session_lock:
            if session_id not in user_sessions:
                # 新会话：创建独立的内存实例
                user_sessions[session_id] = ConversationBufferWindowMemory(
                    k=1,  # 保留最近 1 轮历史对话（减少 token 消耗，避免上下文过长）
                    memory_key="history",  # 与 Prompt 中的{history}变量对应
                    input_key="input",     # 与 Agent 输入变量对应
                    output_key='output'    # 与 Agent 输出变量对应
                )
            # English requests use a fresh memory object so a previous
            # Chinese turn cannot enter the English-only model prompt.
            user_memory = user_sessions[session_id]
            if response_language == "en":
                user_memory = ConversationBufferWindowMemory(
                    k=1,
                    memory_key="history",
                    input_key="input",
                    output_key="output",
                )
        
        # 从 Redis 加载历史对话（独立于锁，避免阻塞）
        history = await get_session_history(session_id)
        if response_language == "zh":
            for msg in history:
                if msg.get("type") == "human":
                    user_memory.chat_memory.add_user_message(msg.get("data", {}).get("content", ""))
                elif msg.get("type") == "ai":
                    user_memory.chat_memory.add_ai_message(msg.get("data", {}).get("content", ""))
        
        # 保存当前场景到 Redis
        try:
            mgr = await get_redis_manager_instance()
            await mgr.set_session_scene(session_id, scene)
        except Exception as e:
            app_logger.debug(f"保存会话场景失败：{e}")

        # ============================================
        # Token 预算检查 & 动态 max_tokens 计算
        # ============================================
        # 【当前模型配置】32K 上下文 = 32768 tokens
        MODEL_MAX_TOKENS = LLM_MAX_CONTEXT_TOKENS
        SAFETY_MARGIN = LLM_SAFETY_MARGIN
        MIN_OUTPUT_TOKENS = LLM_MIN_OUTPUT_TOKENS
        MAX_OUTPUT_TOKENS = min(LLM_MAX_OUTPUT_TOKENS, AGENT_OUTPUT_TOKEN_CAP)

        def _safe_output_budget(prompt_tokens: int) -> int:
            """Never request more tokens than the provider context can hold."""
            available = MODEL_MAX_TOKENS - prompt_tokens - SAFETY_MARGIN
            if available <= 0:
                app_logger.warning(
                    "[Token Budget] prompt already consumes the context window: %s tokens",
                    prompt_tokens,
                )
                return 1
            return min(MAX_OUTPUT_TOKENS, available)

        def _prompt_history() -> str:
            # Do not feed a previous Chinese conversation into an English-only
            # prompt.  The original request remains the sole language source.
            if not is_chinese_input:
                return ""
            return user_memory.load_memory_variables({}).get("history", "")
        
        # 构建完整 prompt 估算总长度
        try:
            prompt_text = prompt_template_agent.format(
                input=user_input,
                intermediate_steps=[],
                history=_prompt_history()
            )
            app_logger.info(f"[Prompt] 初始 prompt 长度：{len(prompt_text)} 字符")
            app_logger.info(f"[Prompt] 完整 prompt 内容:\n{prompt_text}\n[END prompt]")
            prompt_tokens = _estimate_tokens(prompt_text)
            app_logger.info(f"[Token Budget] 初始 prompt tokens: {prompt_tokens}")
            
            # 动态计算 max_tokens：确保 total_tokens <= MODEL_MAX_TOKENS。
            # 工具 Observation 在后续轮次会被压缩，且模型输出有硬上限。
            max_tokens = _safe_output_budget(prompt_tokens)
            
            # 如果 prompt 太长，逐步缩减历史记忆 k 值
            if max_tokens < MIN_OUTPUT_TOKENS:
                original_k = int(user_sessions[session_id].k)
                for k in range(original_k, 0, -2):
                    user_sessions[session_id].k = k
                    prompt_text = prompt_template_agent.format(
                        input=user_input,
                        intermediate_steps=[],
                        history=_prompt_history()
                    )
                    prompt_tokens = _estimate_tokens(prompt_text)
                    max_tokens = _safe_output_budget(prompt_tokens)
                    if max_tokens >= MIN_OUTPUT_TOKENS:
                        app_logger.info(f"[Token Budget] 历史 k: {original_k} → {k}，prompt tokens: {prompt_tokens}，max_tokens: {max_tokens}")
                        break
            else:
                app_logger.info(f"[Token Budget] 无需缩减历史，max_tokens: {max_tokens}")
                
        except Exception as e:
            app_logger.info(f"[Token Budget] Token 估算失败，使用默认值：{e}")
            max_tokens = min(LLM_MAX_OUTPUT_TOKENS, AGENT_OUTPUT_TOKEN_CAP)
        
        app_logger.info(
            "[Token Budget] final max_tokens=%s, context_limit=%s, output_cap=%s",
            max_tokens,
            MODEL_MAX_TOKENS,
            MAX_OUTPUT_TOKENS,
        )
        
        # 初始化模型（使用动态计算的 max_tokens）
        model = ChatOpenAI(
            streaming=True,
            verbose=False,  # 关闭详细日志
            callbacks=[callback],  # 绑定当前请求的独立回调
            openai_api_key=LLM_API_KEY,
            openai_api_base=f'{LLM_BASE_URL}/v1',
            model_name=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            max_tokens=max_tokens,  # ← 动态计算，不再写死
            request_timeout=LLM_CALL_TIMEOUT,
            # 【修复】通过 extra_body 传递 chat_template_kwargs 以兼容不同的 Qwen3 部署方式
            # vLLM 部署使用 chat_template_kwargs；某些自定义服务使用 enable_thinking
            # 两者都放在 extra_body 里，OpenAI client 不会校验，由服务端决定用哪个
            model_kwargs={
                "extra_body": {
                    "enable_thinking": LLM_ENABLE_THINKING,
                    "chat_template_kwargs": {"enable_thinking": LLM_ENABLE_THINKING}
                }
            }
        )

        # 6. 初始化LLM Chain：使用当前请求的独立模型和Prompt
        llm_chain = LLMChain(llm=model, prompt=prompt_template_agent)

        # 7. 实例化输出解析器（无状态，可复用，但为一致性仍独立创建）
        output_parser = CustomOutputParser(
            is_chinese=is_chinese_input,
            original_user_input=user_input,
        )

        # 8. 初始化Agent：使用当前请求的独立工具名列表
        agent = LLMSingleActionAgent(
            llm_chain=llm_chain,
            output_parser=output_parser,
            # stop=["\nObservation:", "Observation"],  # 停止符，避免工具输出混淆
            stop=["\nObservation:", "Observation"],  # 停止符，避免工具输出混淆
            allowed_tools=local_tool_names,  # 替换为局部工具名列表
        )

        # 9. 初始化Agent执行器：使用 EarlyStopAgentExecutor 支持提前终止
        agent_executor = EarlyStopAgentExecutor(
            agent=agent,
            tools=local_tools,  # 替换为局部工具
            verbose=False,  # 生产环境关闭 verbose，减少日志冗余
            memory=user_memory,  # 绑定当前会话的独立内存
            return_intermediate_steps=True,  # 保留中间步骤（工具调用记录）
            handle_parsing_errors=True,  # 自动处理解析错误，避免崩溃
            max_iterations=max_iterations,  # 使用动态设置的迭代次数
        )

        # 10. 启动Agent任务（带done事件回调，确保任务结束信号正确）
        executor_coro = agent_executor.acall(
            user_input,
            callbacks=[callback],
            include_run_info=True
        )
        # 保存 executor 协程的引用，供 on_tool_end 在 early stop 时取消
        callback.task_ref = asyncio.create_task(
            executor_coro, name="executor_coroutine"
        )
        task = asyncio.create_task(wrap_done(
            callback.task_ref,
            callback.done
        ))
        # 11. 流式响应处理：思考增量单独推送，正式答案在 agent_finish 时推送
        collected_answer = ""  # 保留原始模型输出用于诊断日志
        tool_call_count = 0
        model_status_sent = False
        final_answer_sent = False
        stream_error = ""
        
        # 存储 graph_data 供最终答案使用
        latest_graph_data = None
        # 存储 trace_info 供最终答案后推送
        latest_trace_info = None
        latest_tool_output_obj = None
        latest_tool_name = ""

        async for chunk in callback.aiter():
            data = json.loads(chunk)
            status = data.get("status")
            
            if status == Status.tool_start:
                tool_call_count += 1
                latest_tool_name = data.get("tool_name", "") or latest_tool_name
                stream_state["latest_tool_name"] = latest_tool_name
                tools_use = [f"\n {str_lang['start_exec_tool']}"]
                yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
            
            elif status == Status.agent_action:
                input_str = data.get("input_str", "")
                if input_str:
                    try:
                        input_obj = json.loads(input_str)
                        tool_name = data.get("tool_name", "")
                        latest_tool_name = tool_name or latest_tool_name
                        stream_state["latest_tool_name"] = latest_tool_name
                        tools_use = [f"\n {str_lang['call_tool']}: {tool_name}"]
                        yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
                    except json.JSONDecodeError:
                        pass
            
            elif status == Status.tool_finish:
                # app_logger.info(f"\n{'='*60}")
                # app_logger.info(f"=== agent_chat tool_finish DEBUG ===")
                # app_logger.info(f"{'='*60}")
                # app_logger.info(f"status = {status}, Status.tool_finish = {Status.tool_finish}")
                output_str = data.get("output_str", "")
                latest_graph_data = None
                # 【新增】直接从 data 中获取 graph_data（来自 sever.py 的 on_tool_end）
                graph_data_from_sever = data.get("graph_data", None)
                if graph_data_from_sever:
                    latest_graph_data = graph_data_from_sever
                # 【新增】从 data 中获取 trace_info（来自 sever.py 的 on_tool_end），供后续推送
                trace_info_from_sever = data.get("trace_info", None)
                if trace_info_from_sever:
                    latest_trace_info = trace_info_from_sever
                # app_logger.info(f"output_str 总长度：{len(output_str)}")
                # app_logger.info(f"\n【完整 output_str 内容】:")
                # app_logger.info(f"{output_str}")
                # app_logger.info(f"\n【END output_str】")
                
                # 检测工具返回是否包含"最终答案："前缀，直接返回
                final_prefix_match = re.match(r"^(?:最终答案|Final Answer)\s*[:：]\s*", output_str, re.IGNORECASE)
                if final_prefix_match:
                    # 【新增】尝试从 output_str 中解析 JSON 获取 graph_data
                    local_graph_data = None
                    try:
                        output_obj_for_final = json.loads(output_str)
                        trace_info_for_final = output_obj_for_final.get("trace_info", {})
                        if isinstance(trace_info_for_final, dict) and trace_info_for_final.get("graph_data"):
                            local_graph_data = trace_info_for_final.get("graph_data")
                    except (json.JSONDecodeError, TypeError):
                        pass
                    
                    raw_final_answer = output_str[final_prefix_match.end():].strip()
                    thought_text, final_answer_content = split_thoughts(raw_final_answer)
                    if thought_text:
                        yield json.dumps(
                            {"answer": _safe_intermediate_text(thought_text)},
                            ensure_ascii=False,
                        ) + "\n\n"
                    # 如果有 graph_data，一并推送（优先使用 local_graph_data，否则使用 latest_graph_data）
                    graph_data_to_push = local_graph_data or latest_graph_data
                    if _is_incomplete_agent_answer(final_answer_content):
                        final_answer_content = _deterministic_final_fallback(
                            latest_tool_output_obj,
                            latest_tool_name,
                        )
                    else:
                        final_answer_content = _safe_final_text(final_answer_content)
                    final_answer_sent = True
                    if graph_data_to_push:
                        yield json.dumps({'final_answer': final_answer_content, 'graph_data': graph_data_to_push, 'is_final': True, 'format': 'markdown'}, ensure_ascii=False) + "\n\n"
                    else:
                        yield json.dumps({'final_answer': final_answer_content, 'is_final': True, 'format': 'markdown'}, ensure_ascii=False) + "\n\n"
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    return
                
                if output_str:
                    try:
                        output_obj = json.loads(output_str)
                        latest_tool_output_obj = output_obj
                        stream_state["latest_tool_output"] = output_obj
                        stream_state["latest_tool_name"] = (
                            data.get("tool_name", "")
                            or latest_tool_name
                            or stream_state["latest_tool_name"]
                        )
                        latest_tool_name = stream_state["latest_tool_name"]
                        _register_allowed_raw_values(output_obj)
                        steps = output_obj.get("steps", [])
                        http_status = output_obj.get("http_status", 0)
                        count = output_obj.get("count", 0)
                        # app_logger.info(f"steps count: {len(steps)}")
                        # app_logger.info(f"http_status: {http_status}, count: {count}")
                        # app_logger.info(f"=== end ===\n")
                        
                        # 【关键修复】HTTP 200 时，根据原始记录数判断是否为空结果
                        if http_status == 200:
                            # 先展示步骤
                            if steps:
                                tools_use = [
                                    "\n" + "="*50,
                                    str_lang["query_flow"],
                                    "="*50
                                ]
                                for step in steps:
                                    step_num = step.get("step", "")
                                    step_title = step.get("title", "")
                                    step_detail = step.get("detail", "")
                                    is_code = step.get("is_code", False)
                                    tools_use.append(f"\n{str_lang['step_prefix']}{step_num}: {step_title}")
                                    if is_code:
                                        tools_use.append("```")
                                        tools_use.append(step_detail)
                                        tools_use.append("```")
                                    else:
                                        tools_use.append(f"   {step_detail}")
                                    tools_use.append("")
                                tools_use.extend([
                                    "=" * 50,
                                    f"{str_lang['query_complete']}{count}{str_lang['records_suffix']}",
                                    "=" * 50
                                ])
                                # 保存 graph_data 供最终答案使用
                                # 【修复】从 ip_details 中提取所有 IP 的 graph_data 并合并
                                trace_info = output_obj.get("trace_info", {})
                                if not isinstance(trace_info, dict):
                                    trace_info = {}
                                # brute_force nests ip_details under trace_info;
                                # a few legacy tools return it at the top level.
                                ip_details = trace_info.get("ip_details") or output_obj.get("ip_details", [])
                                
                                combined_graph_data = None
                                if isinstance(trace_info, dict) and trace_info.get("graph_data"):
                                    # 直接从 trace_info 获取（ip_trace 工具直调场景）
                                    latest_graph_data = trace_info.get("graph_data")
                                elif isinstance(ip_details, list) and ip_details:
                                    # brute_force 自动溯源场景：从 ip_details 中提取每个 IP 的 graph_data
                                    all_render_lines = []
                                    graph_entries = []
                                    trace_ips = [
                                        ip for ip in trace_info.get("trace_ips", [])
                                        if ip
                                    ]
                                    details = [
                                        detail for detail in ip_details
                                        if isinstance(detail, dict) and detail.get("ip")
                                    ]
                                    if trace_ips:
                                        detail_by_ip = {d.get("ip"): d for d in details}
                                        ordered_details = [
                                            detail_by_ip[ip] for ip in trace_ips
                                            if ip in detail_by_ip
                                        ]
                                    else:
                                        ordered_details = sorted(
                                            details,
                                            key=lambda d: (
                                                d.get("rank") is None,
                                                d.get("rank", 0),
                                            ),
                                        )
                                    for detail in ordered_details[:3]:
                                        # app_logger.info(f"[DEBUG] Detail keys: {list(detail.keys())}, has_graph: {bool(detail.get('graph_data'))}")
                                        if isinstance(detail, dict):
                                            # 直接获取 graph_data (brute_force 返回结构)
                                            ip_gd = detail.get("graph_data")
                                            # 备用：如果嵌套在 trace_info 中 (某些特殊情况)
                                            if not ip_gd and detail.get("trace_info"):
                                                ip_gd = detail.get("trace_info", {}).get("graph_data")
                                            
                                            if isinstance(ip_gd, dict):
                                                graph_entries.append({
                                                    "ip": detail.get("ip", ""),
                                                    "rank": detail.get("rank"),
                                                    "brute_force_count": detail.get("brute_force_count", 0),
                                                    "trace_event_count": detail.get("trace_event_count", 0),
                                                    "time_window": detail.get("time_window", ""),
                                                    "graph_data": ip_gd,
                                                })
                                            if isinstance(ip_gd, dict) and ip_gd.get("render_lines"):
                                                all_render_lines.extend(
                                                    line for line in ip_gd.get("render_lines", [])
                                                    if isinstance(line, dict)
                                                )
                                    
                                    if all_render_lines or graph_entries:
                                        render_by_id = {}
                                        for line in all_render_lines:
                                            line_id = line.get("line_id")
                                            if not line_id:
                                                continue
                                            if line_id not in render_by_id:
                                                render_by_id[line_id] = dict(line)
                                                continue
                                            current = render_by_id[line_id]
                                            current["count"] = int(current.get("count", 0) or 0) + int(line.get("count", 0) or 0)
                                            for field in ("first_seen", "last_seen"):
                                                incoming = line.get(field, "")
                                                existing = current.get(field, "")
                                                if incoming and (not existing or (field == "first_seen" and incoming < existing) or (field == "last_seen" and incoming > existing)):
                                                    current[field] = incoming
                                        merged_lines = list(render_by_id.values())
                                        combined_graph_data = {
                                            "render_lines": merged_lines,
                                            "graphs": graph_entries,
                                            "stats": {
                                                "event_count": sum(int(line.get("count", 0) or 0) for line in merged_lines),
                                                "line_count": len(merged_lines),
                                                "upper_line_count": sum(1 for line in merged_lines if line.get("direction") == "upper"),
                                                "lower_line_count": sum(1 for line in merged_lines if line.get("direction") == "lower"),
                                                "ip_count": len(graph_entries),
                                            },
                                        }
                                        latest_graph_data = combined_graph_data
                                    else:
                                        latest_graph_data = None
                                else:
                                    # 兜底：如果没有 ip_details，且 trace_info 中有 graph_data
                                    if isinstance(trace_info, dict) and trace_info.get("graph_data"):
                                        latest_graph_data = trace_info.get("graph_data")
                                    else:
                                        latest_graph_data = None

                                # Always expose the query-flow event.  Graph
                                # payloads are delivered separately after the
                                # final answer; a non-empty graph must not hide
                                # the tool steps from the single think region.
                                yield json.dumps(
                                    _safe_tools_payload({'tools': tools_use}),
                                    ensure_ascii=False,
                                ) + "\n\n"
                            
                            # 【关键修复】HTTP 200 且 count=0 时，跳过后续处理，让 LLM 进入 agent_finish 生成最终答案
                            if count == 0:
                                # 跳过后续的 if steps 块，避免再次推送工具结果导致 LLM 继续迭代
                                # LLM 会根据提示词生成"未查询到相关数据"的答案
                                continue
                            
                            # 有数据时，跳过后续重复的步骤展示
                            continue
                        
                        # HTTP 非 200 时，检查是否有 __agent_stop__ 标记（early stop 兜底）
                        if output_obj.get("__agent_stop__"):
                            # Early stop 兜底：展示步骤信息，然后 continue 让 agent_finish 事件处理最终答案
                            if steps:
                                tools_use = [
                                    "\n" + "="*50,
                                    str_lang["query_flow"],
                                    "="*50
                                ]
                                
                                for step in steps:
                                    step_num = step.get("step", "")
                                    step_title = step.get("title", "")
                                    step_detail = step.get("detail", "")
                                    is_code = step.get("is_code", False)
                                    
                                    tools_use.append(f"\n{str_lang['step_prefix']}{step_num}: {step_title}")
                                    
                                    if is_code:
                                        tools_use.append("```")
                                        tools_use.append(step_detail)
                                        tools_use.append("```")
                                    else:
                                        tools_use.append(f"   {step_detail}")
                                    
                                    tools_use.append("")
                                
                                tools_use.extend([
                                    "=" * 50,
                                    f"{output_obj.get('error', '查询失败')}",
                                    "=" * 50
                                ])
                                yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
                            else:
                                no_index_text = (
                                    f"\n工具执行完成 (索引不存在): {output_obj.get('error', '查询失败')}"
                                    if is_chinese_input
                                    else f"\nTool execution completed (index not found): {output_obj.get('error', 'Query failed')}"
                                )
                                yield json.dumps(_safe_tools_payload({'tools': [no_index_text]}), ensure_ascii=False) + "\n\n"
                            # 不 return，继续循环处理 agent_finish 事件
                            continue

                        # HTTP 非 200 时，检查是否有 suggestion 字段（free_query 的 3 次重试兜底）
                        if http_status != 200:
                            if 'suggestion' in output_obj and output_obj['suggestion']:
                                # free_query 已经完成了 3 次重试，直接返回兜底建议
                                default_query_error = '查询失败' if is_chinese_input else 'Query failed'
                                final_output = output_obj.get('error', default_query_error) + "\n\n" + output_obj['suggestion']
                                thought_text, final_output = split_thoughts(final_output)
                                if thought_text:
                                    yield json.dumps(
                                        {"answer": _safe_intermediate_text(thought_text)},
                                        ensure_ascii=False,
                                    ) + "\n\n"
                                # 如果有 graph_data，一并推送
                                final_answer_sent = True
                                final_output = _safe_final_text(final_output)
                                if latest_graph_data:
                                    yield json.dumps({'final_answer': final_output, 'graph_data': latest_graph_data, 'is_final': True, 'format': 'markdown'}, ensure_ascii=False) + "\n\n"
                                else:
                                    yield json.dumps({'final_answer': final_output, 'is_final': True, 'format': 'markdown'}, ensure_ascii=False) + "\n\n"
                                task.cancel()
                                try:
                                    await task
                                except asyncio.CancelledError:
                                    pass
                                return
                            
                            # 否则展示错误步骤，让 LLM 继续迭代
                            if steps:
                                tools_use = [
                                    "\n" + "="*50,
                                    str_lang["query_flow"],
                                    "="*50
                                ]
                                
                                for step in steps:
                                    step_num = step.get("step", "")
                                    step_title = step.get("title", "")
                                    step_detail = step.get("detail", "")
                                    is_code = step.get("is_code", False)
                                    
                                    tools_use.append(f"\n{str_lang['step_prefix']}{step_num}: {step_title}")
                                    
                                    if is_code:
                                        tools_use.append("```")
                                        tools_use.append(step_detail)
                                        tools_use.append("```")
                                    else:
                                        tools_use.append(f"   {step_detail}")
                                    
                                    tools_use.append("")
                                
                                tools_use.extend([
                                    "=" * 50,
                                    f"{str_lang['query_failed']}{http_status}",
                                    "=" * 50
                                ])
                                yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
                                continue
                        
                        if steps:
                            tools_use = [
                                "\n" + "="*50,
                                str_lang["query_flow"],
                                "="*50
                            ]
                            
                            for step in steps:
                                step_num = step.get("step", "")
                                step_title = step.get("title", "")
                                step_detail = step.get("detail", "")
                                is_code = step.get("is_code", False)
                                
                                tools_use.append(f"\n{str_lang['step_prefix']}{step_num}: {step_title}")
                                
                                if is_code:
                                    tools_use.append("```")
                                    tools_use.append(step_detail)
                                    tools_use.append("```")
                                else:
                                    tools_use.append(f"   {step_detail}")
                                
                                tools_use.append("")
                            
                            tools_use.extend([
                                "=" * 50,
                                f"{str_lang['query_complete']}{output_obj.get('count', 0)}{str_lang['records_suffix']}",
                                "=" * 50
                            ])
                        else:
                            tools_use = [f"\n{str_lang['tool_executed']}: {output_str[:200]}..."]
                        
                        yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
                    except json.JSONDecodeError as e:
                        app_logger.info(f"JSON 解析失败：{e}")
                        app_logger.info(f"=== end ===\n")
                        tools_use = [
                            f"\n{str_lang['tool_executed']} ({str_lang['parse_failed']}): {output_str[:200]}..."
                        ]
                        yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
            
            elif status in (Status.start, Status.running):
                llm_token = data.get('llm_token', '')
                collected_answer += llm_token  # 收集原始模型输出用于诊断
                # Never forward raw model reasoning.  It can contain the
                # wrong language (and may expose private chain-of-thought).
                # Emit one server-owned, language-safe status instead.
                if llm_token and tool_call_count == 0 and not model_status_sent:
                    model_status_sent = True
                    yield json.dumps(
                        {"answer": _language_fallback("thought")},
                        ensure_ascii=False,
                    ) + "\n\n"
            
            elif status == Status.error:
                stream_error = data.get('error', '') or stream_error
                tools_use = [
                    f"\n {str_lang['tool_executed_failed']}",
                    f"{str_lang['error_msg']}: {data.get('error', str_lang['unknown_error'])}"
                ]
                yield json.dumps(_safe_tools_payload({'tools': tools_use}), ensure_ascii=False) + "\n\n"
            
            elif status == Status.agent_finish:
                final_answer = data.get("final_answer", "")
                index_check_steps = data.get("steps", [])
                thought_text, final_answer = split_thoughts(final_answer)
                if thought_text:
                    yield json.dumps(
                        {"answer": _safe_intermediate_text(thought_text)},
                        ensure_ascii=False,
                    ) + "\n\n"

                if _is_incomplete_agent_answer(final_answer):
                    recovered_answer = ""
                    if isinstance(latest_tool_output_obj, dict) and latest_tool_output_obj.get("http_status") == 200:
                        from custom_template import compact_observation_for_llm
                        snapshot = compact_observation_for_llm(
                            json.dumps(latest_tool_output_obj, ensure_ascii=False, separators=(",", ":"))
                        )
                        recovery_prefix = (
                            "仅使用下面的工具结果生成完整最终安全报告，不得编造事实。"
                            "所有自然语言必须使用中文，不要输出英文说明。\n\n"
                            if is_chinese_input
                            else
                            "Generate the complete final security report using only the tool result below. "
                            "Do not invent facts. English only: do not output Chinese characters in any prose, "
                            "heading, error, or final_answer.\n\n"
                        )
                        recovery_prompt = (
                            recovery_prefix
                            + f"{_build_recovery_report_template(is_chinese_input)}\n"
                            + f"Tool result:\n{snapshot}"
                        )
                        try:
                            recovered = await asyncio.wait_for(
                                model.ainvoke(recovery_prompt),
                                timeout=LLM_CALL_TIMEOUT,
                            )
                            recovered_answer = getattr(recovered, "content", str(recovered)).strip()
                            if (
                                _is_incomplete_agent_answer(recovered_answer)
                                or not _final_language_ok(recovered_answer)
                            ):
                                recovered_answer = ""
                        except Exception as exc:
                            app_logger.warning(f"[agent_finish] recovery generation failed: {exc}")
                    final_answer = recovered_answer or _deterministic_final_fallback(
                        latest_tool_output_obj,
                        latest_tool_name,
                    )
                # app_logger.info(f"\n{'='*60}")
                # app_logger.info(f"=== agent_finish DEBUG ===")
                # app_logger.info(f"final_answer 长度：{len(final_answer)}")
                # app_logger.info(f"final_answer 前100字符：{final_answer[:100]}")
                # app_logger.info(f"collected_answer 长度：{len(collected_answer)}")
                # app_logger.info(f"latest_trace_info 是否存在：{latest_trace_info is not None}")
                # app_logger.info(f"{'='*60}")
                
                # app_logger.info(f"[DEBUG] Agent Finish: latest_graph_data is {latest_graph_data is not None}")

                # 【修复】用内容比对决定是否推 final_answer（避免 locals() 跨作用域问题）
                should_push_final = False
                reason = ""

                # 兜底：如果 final_answer 为空但 steps 有错误信息（如索引不存在）
                if not final_answer and index_check_steps:
                    error_msg = (
                        "查询失败，未找到相关日志索引"
                        if is_chinese_input
                        else "Query failed: no matching log index was found"
                    )
                    for step in index_check_steps:
                        if "不存在" in step.get("detail", "") or step.get("title") == "索引存在性探测":
                            error_msg = step.get("detail", error_msg)
                            break
                    if "不存在" not in error_msg:
                        error_msg = (
                            "该索引不存在，已为您关闭日志查询功能"
                            if is_chinese_input
                            else "The index does not exist, so the log query was closed."
                        )
                    final_answer = error_msg
                    if not _final_language_ok(final_answer):
                        final_answer = _localized_fixed_error(final_answer, latest_tool_output_obj)
                        if not _final_language_ok(final_answer):
                            final_answer = _language_fallback("final")
                    app_logger.info(f"[agent_finish] 从步骤信息构造 final_answer: {final_answer}")

                # Repair a completed answer when the model ignores the request language.
                # Raw tool values, field names, IPs, and timestamps are preserved by the prompt.
                needs_chinese_repair = is_chinese_input and (
                    not _contains_cjk(final_answer) or "## 1. Event Summary" in final_answer
                )
                needs_english_repair = not is_chinese_input and _contains_cjk(final_answer)
                if needs_chinese_repair or needs_english_repair:
                    fixed_error = _localized_fixed_error(final_answer, latest_tool_output_obj)
                    if _final_language_ok(fixed_error):
                        final_answer = fixed_error
                        needs_chinese_repair = False
                        needs_english_repair = False
                if needs_chinese_repair or needs_english_repair:
                    try:
                        target_language = "Chinese" if is_chinese_input else "English"
                        if is_chinese_input:
                            translation_prompt = (
                                "请将下面的安全分析完整转换为中文。只输出转换后的答案，不要添加前言或解释。"
                                "必须保留全部事实、数量、IP、时间戳、字段名和 Markdown 结构，并使用中文标题。\n\n"
                                f"待转换答案：\n{final_answer}"
                            )
                        else:
                            translation_prompt = (
                                "Translate the following security-analysis answer into English. "
                                "Output only the translated answer, with no preface or explanation. "
                                "Preserve all facts, counts, IP addresses, timestamps, field names, and Markdown structure. "
                                "Do not output Chinese characters.\n\n"
                                f"Answer to translate:\n{final_answer}"
                            )
                        translated = await asyncio.wait_for(
                            model.ainvoke(translation_prompt),
                            timeout=LLM_CALL_TIMEOUT,
                        )
                        translated_text = getattr(translated, "content", str(translated)).strip()
                        language_ok = _final_language_ok(translated_text)
                        if translated_text and language_ok:
                            final_answer = translated_text
                        else:
                            raise ValueError("translation still contains CJK characters")
                    except Exception as exc:
                        app_logger.warning(f"[agent_finish] {target_language} answer translation failed: {exc}")
                        final_answer = _deterministic_final_fallback(
                            latest_tool_output_obj,
                            latest_tool_name,
                        )

                if final_answer:
                    # Raw model tokens are never sent as ``answer`` anymore, so
                    # the cleaned final answer is always the authoritative event.
                    should_push_final = True
                    reason = "final_answer authoritative event"

                # 无论是否推送到 SSE，始终记录完整 final_answer
                app_logger.info(f"[agent_finish] 最终输出 (pushed={should_push_final}, reason={reason}, len={len(final_answer)}): {final_answer}")

                if should_push_final:
                    final_answer_sent = True
                    # Tool steps have already been emitted inside the single
                    # server-owned think region; keep the final event limited
                    # to the public answer contract.
                    yield json.dumps({"final_answer": clean_final_answer(final_answer), "is_final": True, "format": "markdown"}, ensure_ascii=False) + "\n\n"

                # 【修复】流完后只推一次 graph_data（精简版），作为"处理完成"信号
                if latest_trace_info or latest_graph_data:
                    slim_trace = {
                        "type": "graph_data",
                        "status": "success",
                        "ip_count": latest_trace_info.get("ip_count", 0) if latest_trace_info else 0,
                        "time_window": latest_trace_info.get("time_window", "") if latest_trace_info else "",
                        "trace_ips": list(latest_trace_info.get("trace_ips", []))[:3] if latest_trace_info else [],
                        "graphs": []
                    }
                    if latest_trace_info and latest_trace_info.get("ip_details"):
                        # Keep completion graphs in the same rank/IP order as
                        # brute_force.trace_ips.  Do not merge different IPs
                        # into one graph or expose traces beyond the selected
                        # Top3 list.
                        details = [
                            d for d in latest_trace_info.get("ip_details", [])
                            if isinstance(d, dict) and d.get("ip")
                        ]
                        trace_ips = [
                            ip for ip in latest_trace_info.get("trace_ips", [])
                            if ip
                        ]
                        if trace_ips:
                            detail_by_ip = {d.get("ip"): d for d in details}
                            ordered_details = [
                                detail_by_ip[ip] for ip in trace_ips
                                if ip in detail_by_ip
                            ]
                        else:
                            ordered_details = sorted(
                                details,
                                key=lambda d: (
                                    d.get("rank") is None,
                                    d.get("rank", 0),
                                ),
                            )
                        for d in ordered_details[:3]:
                            slim_trace["graphs"].append({
                                "ip": d.get("ip", ""),
                                "rank": d.get("rank"),
                                "brute_force_count": d.get("brute_force_count", 0),
                                "trace_event_count": d.get("trace_event_count", 0),
                                "time_window": d.get("time_window", ""),
                                "graph_data": d.get("graph_data", {}),
                            })
                    elif latest_graph_data:
                        # A direct ip_trace call may provide a single graph;
                        # a normalized brute-force payload may already contain
                        # the per-IP ``graphs`` list.  Preserve that list
                        # instead of collapsing it into an anonymous graph.
                        if isinstance(latest_graph_data, dict) and isinstance(
                            latest_graph_data.get("graphs"), list
                        ):
                            slim_trace["graphs"] = [
                                graph for graph in latest_graph_data["graphs"][:3]
                                if isinstance(graph, dict)
                            ]
                        else:
                            slim_trace["graphs"].append({
                                "ip": latest_graph_data.get("ip", "")
                                if isinstance(latest_graph_data, dict) else "",
                                "rank": latest_graph_data.get("rank")
                                if isinstance(latest_graph_data, dict) else None,
                                "brute_force_count": latest_graph_data.get("brute_force_count", 0)
                                if isinstance(latest_graph_data, dict) else 0,
                                "trace_event_count": latest_graph_data.get("trace_event_count", 0)
                                if isinstance(latest_graph_data, dict) else 0,
                                "time_window": latest_graph_data.get("time_window", "")
                                if isinstance(latest_graph_data, dict) else "",
                                "graph_data": latest_graph_data,
                            })

                    slim_size = len(json.dumps(slim_trace, ensure_ascii=False))
                    app_logger.info(f"[agent_finish] 推送精简 graph_data，大小：{slim_size} 字符（作为完成信号）")
                    yield json.dumps(slim_trace, ensure_ascii=False) + "\n\n"
                    app_logger.info(f"[agent_finish] graph_data event pushed (完成信号)")

                    # 强制刷新
                    await asyncio.sleep(0.1)
                    app_logger.info("[agent_finish] SSE buffer flushed")

                if final_answer:
                    try:
                        mgr = await get_redis_manager_instance()
                        # 获取现有历史
                        existing_history = await mgr.get_session(session_id)
                        # 追加新对话
                        new_history = existing_history + [
                            {"type": "human", "request_id": request_id, "data": {"content": user_input}},
                            {"type": "ai", "request_id": request_id, "data": {"content": final_answer}}
                        ]
                        # 保留最近 10 轮对话（与内存缓存 k=5 对应，每轮 2 条消息）
                        new_history = new_history[-20:]
                        await mgr.save_session(session_id, new_history)
                    except Exception as e:
                        app_logger.warning(f"保存会话历史失败：{e}")
                    try:
                        await mgr.save_request_log(
                            session_id,
                            request_id,
                            {
                                "request_id": request_id,
                                "session_id": session_id,
                                "login_account": login_account,
                                "status": "completed",
                                "user_input": user_input,
                                "final_answer": final_answer,
                                "history_count": len(new_history) if 'new_history' in locals() else None,
                            },
                        )
                    except Exception as e:
                        app_logger.warning(f"保存请求完成日志失败：request_id={request_id}, error: {e}")
                # 退出循环
                break
        if not final_answer_sent:
            fallback_answer = _deterministic_final_fallback(
                latest_tool_output_obj,
                latest_tool_name,
            )
            app_logger.warning(
                f"[agent_chat] 未收到 final_answer，发送统一兜底完成事件: {stream_error or 'unknown error'}"
            )
            yield json.dumps({
                "final_answer": fallback_answer,
                "is_final": True,
                "format": "markdown",
                "error": stream_error or None,
            }, ensure_ascii=False) + "\n\n"
        # 等待任务完成，释放资源
        await task

    async def protocolized_iterator(source):
        """Normalize legacy inner events into one server-owned think region."""
        think_open = False
        think_closed = False
        final_seen = False

        def encode(payload):
            return json.dumps(payload, ensure_ascii=False) + "\n\n"

        def open_think():
            nonlocal think_open
            if think_open:
                return []
            think_open = True
            return [encode({"answer": "<think>\n"})]

        def close_think():
            nonlocal think_open, think_closed
            if think_closed:
                return []
            if not think_open:
                think_open = True
            think_closed = True
            # Close the region together with a language-owned status message;
            # never emit an event whose only content is ``</think>``.
            closing_text = (
                "工具及中间处理已完成。\n</think>\n"
                if response_language == "zh"
                else "Tool and intermediate processing completed.\n</think>\n"
            )
            return [encode({"answer": closing_text})]

        tag_re = re.compile(r"</?(?:think|thinking|antThinking)\s*/?>", re.IGNORECASE)
        tag_prefixes = ("<think", "<thinking", "<antthinking", "</think", "</thinking", "</antthinking")
        tag_pending = ""

        def sanitize_answer_chunk(value: str, flush: bool = False) -> str:
            """Remove model tags while handling tags split across SSE tokens."""
            nonlocal tag_pending
            tag_pending += str(value or "")
            output = []
            while tag_pending:
                match = tag_re.search(tag_pending)
                if match:
                    output.append(tag_pending[:match.start()])
                    tag_pending = tag_pending[match.end():]
                    continue
                if not flush:
                    keep = 0
                    lowered = tag_pending.lower()
                    for size in range(1, min(len(lowered), 16) + 1):
                        if any(prefix.startswith(lowered[-size:]) for prefix in tag_prefixes):
                            keep = size
                    if keep:
                        output.append(tag_pending[:-keep])
                        tag_pending = tag_pending[-keep:]
                        break
                output.append(tag_pending)
                tag_pending = ""
            return "".join(output)

        try:
            async for raw_event in source:
                try:
                    payload = json.loads(raw_event.strip()) if isinstance(raw_event, str) else raw_event
                except (TypeError, json.JSONDecodeError):
                    if not think_closed:
                        for event in open_think():
                            yield event
                    raw_text = _safe_intermediate_text(str(raw_event or ""))
                    if raw_text:
                        yield encode({"answer": raw_text})
                    continue

                if not isinstance(payload, dict):
                    continue

                if "final_answer" in payload:
                    if final_seen:
                        # The executor/callback can report completion twice;
                        # keep one final_answer event and allow graph_data to
                        # remain available through its dedicated event.
                        if "graph_data" in payload:
                            yield encode({
                                key: value for key, value in payload.items()
                                if key != "final_answer"
                            })
                        continue
                    pending_content = sanitize_answer_chunk("", flush=True)
                    if pending_content and not think_closed:
                        for event in open_think():
                            yield event
                        yield encode({"answer": _safe_intermediate_text(pending_content)})
                    for event in open_think():
                        yield event
                    for event in close_think():
                        yield event
                    final_text = clean_final_answer(str(payload.get("final_answer") or "")).strip()
                    if _is_incomplete_agent_answer(final_text):
                        final_text = _deterministic_final_fallback(
                            stream_state["latest_tool_output"],
                            stream_state["latest_tool_name"],
                        )
                    if not final_text:
                        final_text = _deterministic_final_fallback(
                            stream_state["latest_tool_output"],
                            stream_state["latest_tool_name"],
                        )
                    elif not _final_language_ok(final_text):
                        final_text = _language_fallback("final")
                    payload["final_answer"] = final_text
                    # Steps are intermediate tool content and must remain in
                    # the single think region, never in the final event.
                    payload.pop("steps", None)
                    payload.setdefault("is_final", True)
                    payload.setdefault("format", "markdown")
                    final_seen = True
                    yield encode(payload)
                    continue

                if "tools" in payload:
                    if think_closed:
                        app_logger.warning("[SSE] suppressed tools event after </think>")
                        continue
                    for event in open_think():
                        yield event
                    yield encode(_safe_tools_payload(payload))
                    continue

                if "answer" in payload:
                    if think_closed:
                        app_logger.warning("[SSE] suppressed answer event after </think>")
                        continue
                    content = sanitize_answer_chunk(payload.get("answer") or "")
                    content = _safe_intermediate_text(content)
                    if not content:
                        continue
                    for event in open_think():
                        yield event
                    yield encode({"answer": content})
                    continue

                # Preserve graph_data completion events after final_answer for
                # frontend rendering. Other intermediate events remain blocked
                # after the think region has been closed.
                if final_seen:
                    if "graph_data" in payload or payload.get("type") == "graph_data":
                        yield encode(payload)
                    continue
                for event in open_think():
                    yield event
                yield encode(payload)
            # A source that ends without an explicit final event must still
            # close the single server-owned think region and emit a valid
            # language-matched completion event.
            if not final_seen:
                pending_content = sanitize_answer_chunk("", flush=True)
                if pending_content:
                    for event in open_think():
                        yield event
                    yield encode({"answer": _safe_intermediate_text(pending_content)})
                for event in open_think():
                    yield event
                for event in close_think():
                    yield event
                yield encode({
                    "final_answer": _deterministic_final_fallback(
                        stream_state["latest_tool_output"],
                        stream_state["latest_tool_name"],
                    ),
                    "is_final": True,
                    "format": "markdown",
                })
        except Exception as exc:
            app_logger.exception("[SSE] stream normalization failed: %s", exc)
            if not final_seen:
                pending_content = sanitize_answer_chunk("", flush=True)
                if pending_content:
                    for event in open_think():
                        yield event
                    yield encode({"answer": _safe_intermediate_text(pending_content)})
                for event in open_think():
                    yield event
                for event in close_think():
                    yield event
                yield encode({
                    "final_answer": _deterministic_final_fallback(
                        stream_state["latest_tool_output"],
                        stream_state["latest_tool_name"],
                    ),
                    "is_final": True,
                    "format": "markdown",
                    "error": str(exc),
                })

    # 返回流式响应
    app_logger.info(f"[响应] HTTP 200 | 正常流式响应 | request_id: {request_id}, session_id: {session_id}, user_input: {user_input}")
    return EventSourceResponse(
        protocolized_iterator(agent_chat_iterator(user_input, scoped_session_id, request_id)),
        headers={"X-Request-ID": request_id},
    )


if __name__ == '__main__':
    # 启动UVicorn服务：绑定127.0.0.1:20005，日志级别info
    uvicorn.run(
        app,
        host=APP_HOST,
        port=APP_PORT,
        log_level=APP_LOG_LEVEL,
        timeout_keep_alive=APP_TIMEOUT_KEEP_ALIVE
    )

    # uvicorn.run(
    #     app,
    #     host='127.0.0.1',
    #     port=20010,
    #     log_level='info',
    #     timeout_keep_alive=60
    # )
