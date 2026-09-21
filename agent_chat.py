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
from pathlib import Path
from typing import Awaitable
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
    LLM_MODEL,
    LLM_SAFETY_MARGIN,
    LLM_TEMPERATURE,
)

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
            '【输出格式硬性要求】直接按指定格式输出，禁止输出 <think>...</think> 等任何思考/推理内容！\n'
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
            "【输出格式硬性要求】直接按指定格式输出，禁止输出 <think>...</think> 等任何思考/推理内容！"
            "如果检测到模型进入思考模式，输出将被截断并导致请求失败！"
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
            "- gid: 可选，设备组 ID，当用户明确提到特定设备组或防火墙设备时才传入 gid 参数\n"
            "- user_problem: 直接复制用户问题原文\n\n"
            "【防幻觉规则 - 最重要】\n"
            "- 【关键】所有统计数字必须来自工具返回的 compression.summary_text 或 data 字段，绝不凭空编造数字\n"
            "- 【关键】时间线只能列出工具明确返回的 Top 3 攻击源 IP（不足 3 个就显示有几个就显示几个，不要凑数）。对于未在工具数据中出现的 IP、时间戳、用户名，禁止在时间线中凭空生成！\n"
            "- 【关键】如果工具返回的是聚合统计（例如 54 个 IP 共 1864 条），不要逐个列出 54 个 IP；只列 Top 3（按攻击次数），其余写 另有 X 个 IP 详见原始记录\n"
            "- 【关键】IP 总数必须等于工具返回的 ip_count 字段（或 unique_ips 字段）。如工具返回 ip_count=3，答案里写 3 个 IP 详情 + 0 个其他 IP；如工具返回 ip_count=59，则 Top 3 + 另有 54 个 IP 详见原始记录。**严禁编造或推断 IP 总数**\n"
            "- 【关键】工具未在 data 数组中返回的 IP，禁止出现在最终答案的任何位置（包括 Top 3、剩余 IP、时间线）。如工具 data 里有 3 个 IP，最终答案只能有这 3 个\n"
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
            "- 【关键】只调用一次工具！收到工具返回后直接归纳总结生成最终答案，禁止再次调用工具！\n"
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
            "   如果用户用英文提问：\n"
            "     Question: {input}\n"
            "     Thought: Analyze the user's question and select appropriate tools\n"
            "     Action: Selected tool name\n"
            "     Action Input: {{\"user_problem\": \"...\", \"start_time\": \"...\", \"end_time\": \"...\", \"filter_ip\": \"...\", \"filter_user\": \"...\", \"aggregate\": true/false, \"group_by\": \"...\", \"gid\": \"...\"}}\n\n"
            "   【严禁】在输出行动和行动输入之后，不得继续输出任何查询结果、统计数据或最终答案！\n"
            "   【严禁】不得在工具返回数据之前编造或预测查询结果！\n"
            "   必须等待工具返回真实数据后，才能生成最终答案！\n\n"
            "2. 当收到工具返回后，按以下统一的四段式 Markdown 大纲输出最终答案（不要再次输出 问题/思考/行动/行动输入）：\n"
            "   【格式硬性要求】\n"
            "   - 必须按 ## 1 → ## 2 → ## 3 → ## 4 顺序输出，缺一段即为输出不完整\n"
            "   - 仅在工具数据支持时填写具体数字；工具未给出的字段写 未提供 或留空\n"
            "   - 时间线只展示 Top 3 攻击源 IP（不足 3个就显示有几个就显示几个，不要凑数），剩余写 另有 X 个 IP，详见原始记录\n"
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
            "   - 攻击源 Top N（仅列工具返回的前 5 个 IP，附次数占比，标注内网/公网；不足 5 个就显示有几个就显示几个）：\\n"\
            "     - **重要：IP 次数和占比数据在工具的 `ip_stats` 字段中已预计算好，请直接使用其中的 `count` 和 `percentage` 字段，禁止 LLM 自行计算！**\\n"\
            "     - <IP>：<内网IP/公网IP>，攻击 X 次（占比 Y%），主要行为：<工具返回的具体描述>\n"
            "     - ...\n"
            "   - 目标对象：涉及设备（devname）、目标用户（user Top 3）、目标端口/协议、命中策略 ID（policyid Top 3）\n"
            "   - 账户影响：被锁定的账户（account_locked）、密码错误次数最多的账户、是否存在成功登录\n"
            "   - 综合分析：一句话定性攻击性质（如：内网主机被感染后横向爆破 / 公网 IP 自动化撞库 / 历史攻击复盘等）\n\n"
            "   ## 3. 攻击详细时间线TOP3\n"
            "   每个 IP 一段，按 4 阶段组织（首次探测 → 首次尝试 → 批量爆破 → 最终结果）。时间戳格式：工具返回精确时间戳时用 [HH:MM:SS]，仅有时段时用 约 HH:MM。示例（精确时间戳场景）：\n"
            "   **重要：IP 次数和占比数据在工具的 `ip_stats` 字段中已预计算好，请直接使用其中的 `count` 和 `percentage` 字段，禁止 LLM 自行计算！**\\n"\
            "   攻击源：<IP>（X 次，占 Y%）\n"
            "   - [HH:MM:SS] 【首次探测】访问目标 <设备名> 的 <端口>（协议：<协议>）\n"
            "   - [HH:MM:SS] 【首次尝试】以用户 <user> 身份登录 <设备>，结果：<成功/失败 + 原因>\n"
            "   - [HH:MM:SS] ~ [HH:MM:SS] 【批量爆破】持续尝试，涉及用户 <user1>、<user2>...，共 X 次\n"
            "   - [HH:MM:SS] 【最终结果】攻击停止（原因：<账户锁定/防火墙拦截/攻击结束/成功登录>）\n"
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
        logger.error(f'{e.__class__.__name__}: {msg}',)
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
    login_account = data.get('login_account', '')
    is_admin = bool(data.get('is_admin', False))
    allowed_gids = data.get('allowed_gids', None)

    # ========================================
    # 请求日志
    # ========================================
    app_logger.info(f"\n{'='*60}")
    app_logger.info(f"【请求开始】session_id: {session_id}, user_input: {user_input}")
    app_logger.info(f"  login_account: {login_account}, is_admin: {is_admin}, allowed_gids: {allowed_gids}")
    app_logger.info(f"{'='*60}\n")

    # 【数据权限】参数校验：
    # 1. login_account 必传，缺失直接拒绝请求（防止未鉴权调用拿到全量数据）
    # 2. 非 admin 用户必须携带非空 allowed_gids 白名单
    # 3. admin 用户忽略 allowed_gids，不注入任何过滤
    if not login_account:
        app_logger.warning(f"[响应] HTTP 403 | 缺少 login_account | session_id: {session_id}")
        return JSONResponse(
            status_code=403,
            content={"error": "请求缺少登录账号信息，无法确认您的数据权限，请退出后重新登录再试。"},
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    # 白名单归一化为字符串列表；admin 默认不限制，但如果传入了 allowed_gids 也用于索引探测/效率优化
    if is_admin:
        # 管理员如果有 allowed_gids，用于索引探测和查询优化（仅提高效率，不影响权限）
        normalized_gids = [str(g).strip() for g in (allowed_gids or []) if str(g).strip()] if allowed_gids else None
    else:
        normalized_gids = [str(g).strip() for g in (allowed_gids or []) if str(g).strip()]
        if not normalized_gids:
            app_logger.warning(f"[响应] HTTP 403 | 缺少 allowed_gids | session_id: {session_id}, login_account: {login_account}")
            return JSONResponse(
                status_code=403,
                content={"error": "请求未携带用户组权限信息（allowed_gids），无法确认您的数据权限，请退出后重新登录再试。"},
                headers={"Content-Type": "application/json; charset=utf-8"}
            )

    # 【数据权限】注入 request_ctx（LLM 不可见、不可伪造）
    # is_admin=True -> allowed_gids=None（不限制）；否则为白名单列表
    from tools.tool_base import request_ctx
    request_ctx.set({
        "login_account": login_account,
        "is_admin": is_admin,
        "allowed_gids": normalized_gids
    })

    # 校验必要参数
    if not session_id or not user_input:
        app_logger.warning(f"[响应] HTTP 400 | 缺少 session_id 或 user_input | session_id: {session_id}, user_input: {user_input}")
        return JSONResponse(
            status_code=400,
            content={"error": "session_id和user_input为必填参数"},
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    # Redis 和进程内会话均按账号隔离，避免不同用户复用同一个 session_id 串读历史。
    scoped_session_id = hashlib.sha256(
        f"{login_account}\0{session_id}".encode("utf-8")
    ).hexdigest()

    def _is_chinese(text: str) -> bool:
        """
        判断文本是否包含中文字符
        """
        for char in text:
            if '\u4e00' <= char <= '\u9fff':
                return True
        return False
    
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
                "query_complete": "Query Complete, Total",
                "records_suffix": "records",
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
    
    async def agent_chat_iterator(user_input: str, session_id: str):
        """
        这是流式响应的核心生成器
        """
        # 1. 实例化当前请求独立的回调函数（无共享状态）
        callback = CustomAsyncIteratorCallbackHandler()
        
        # 2. 根据用户输入判断语言
        is_chinese_input = _is_chinese(user_input)
        str_lang = _get_language_strings(is_chinese_input)

        # 2. 工具实例隔离：为当前请求创建独立工具副本（避免全局工具共享冲突）
        # 深拷贝全局tools，确保每个请求的工具状态独立，并提取工具名
        local_tools = [copy.deepcopy(tool) for tool in tools]
        local_tool_names = [tool.name for tool in local_tools]  # 独立的工具名列表
        
        # 使用 auto_select 场景，让大模型根据工具描述自主选择
        scene = "auto_select"
        max_iterations = 3  # 限制最多 3 次迭代，避免多轮思考累积超过 32K 上下文

        # 3. 初始化Prompt模板：使用当前请求的独立工具
        prompt_template = prompts[scene]["format_prompt"]
        prompt_template_agent = CustomPromptTemplate(
            template=prompt_template,
            tools=local_tools,  # 替换为局部工具
            input_variables=["input", "intermediate_steps", "history"]
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
            # 获取当前会话的内存（无论新旧会话都要获取）
            user_memory = user_sessions[session_id]
        
        # 从 Redis 加载历史对话（独立于锁，避免阻塞）
        history = await get_session_history(session_id)
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
        MAX_OUTPUT_TOKENS = LLM_MAX_OUTPUT_TOKENS
        
        # 构建完整 prompt 估算总长度
        try:
            prompt_text = prompt_template_agent.format(
                input=user_input,
                intermediate_steps=[],
                history=user_memory.load_memory_variables({}).get("history", "")
            )
            app_logger.info(f"[Prompt] 初始 prompt 长度：{len(prompt_text)} 字符")
            app_logger.info(f"[Prompt] 完整 prompt 内容:\n{prompt_text}\n[END prompt]")
            prompt_tokens = _estimate_tokens(prompt_text)
            app_logger.info(f"[Token Budget] 初始 prompt tokens: {prompt_tokens}")
            
            # 动态计算 max_tokens：确保 total_tokens <= MODEL_MAX_TOKENS
            # 预留额外余量：Agent 多轮迭代后 prompt 还会变长
            max_tokens = MODEL_MAX_TOKENS - prompt_tokens - SAFETY_MARGIN * 2
            max_tokens = max(max_tokens, MIN_OUTPUT_TOKENS)
            max_tokens = min(max_tokens, MAX_OUTPUT_TOKENS)  # 上限保护
            
            # 如果 prompt 太长，逐步缩减历史记忆 k 值
            if max_tokens < MIN_OUTPUT_TOKENS:
                original_k = int(user_sessions[session_id].k)
                for k in range(original_k, 0, -2):
                    user_sessions[session_id].k = k
                    prompt_text = prompt_template_agent.format(
                        input=user_input,
                        intermediate_steps=[],
                        history=user_sessions[session_id].load_memory_variables({}).get("history", "")
                    )
                    prompt_tokens = _estimate_tokens(prompt_text)
                    max_tokens = MODEL_MAX_TOKENS - prompt_tokens - SAFETY_MARGIN * 2
                    max_tokens = max(max_tokens, MIN_OUTPUT_TOKENS)
                    max_tokens = min(max_tokens, MAX_OUTPUT_TOKENS)
                    if max_tokens >= MIN_OUTPUT_TOKENS:
                        app_logger.info(f"[Token Budget] 历史 k: {original_k} → {k}，prompt tokens: {prompt_tokens}，max_tokens: {max_tokens}")
                        break
            else:
                app_logger.info(f"[Token Budget] 无需缩减历史，max_tokens: {max_tokens}")
                
        except Exception as e:
            app_logger.info(f"[Token Budget] Token 估算失败，使用默认值：{e}")
            max_tokens = min(LLM_MAX_OUTPUT_TOKENS, 15000)
        
        # app_logger.info(f"[Token Budget] 最终 max_tokens = {max_tokens}")
        
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
        output_parser = CustomOutputParser(is_chinese=is_chinese_input)

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
            max_iterations=max_iterations  # 使用动态设置的迭代次数
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
        # 11. 流式响应处理：拼接思考过程，满足条件时推送
        collected_answer = ""  # 收集所有通过 answer 输出的内容，用于保存会话历史
        
        # 存储 graph_data 供最终答案使用
        latest_graph_data = None
        # 存储 trace_info 供最终答案后推送
        latest_trace_info = None

        async for chunk in callback.aiter():
            data = json.loads(chunk)
            status = data.get("status")
            
            if status == Status.tool_start:
                tools_use = [f"\n {str_lang['start_exec_tool']}"]
                yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
            
            elif status == Status.agent_action:
                input_str = data.get("input_str", "")
                if input_str:
                    try:
                        input_obj = json.loads(input_str)
                        tool_name = data.get("tool_name", "")
                        tools_use = [f"\n {str_lang['call_tool']}: {tool_name}"]
                        yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
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
                if output_str.startswith("最终答案："):
                    # 【新增】尝试从 output_str 中解析 JSON 获取 graph_data
                    local_graph_data = None
                    try:
                        output_obj_for_final = json.loads(output_str)
                        trace_info_for_final = output_obj_for_final.get("trace_info", {})
                        if isinstance(trace_info_for_final, dict) and trace_info_for_final.get("graph_data"):
                            local_graph_data = trace_info_for_final.get("graph_data")
                    except (json.JSONDecodeError, TypeError):
                        pass
                    
                    final_answer_content = output_str.replace("最终答案：", "").strip()
                    # 如果有 graph_data，一并推送（优先使用 local_graph_data，否则使用 latest_graph_data）
                    graph_data_to_push = local_graph_data or latest_graph_data
                    if graph_data_to_push:
                        yield json.dumps({'final_answer': final_answer_content, 'graph_data': graph_data_to_push}, ensure_ascii=False) + "\n\n"
                    else:
                        yield json.dumps({'final_answer': final_answer_content}, ensure_ascii=False) + "\n\n"
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    return
                
                if output_str:
                    try:
                        output_obj = json.loads(output_str)
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
                                ip_details = output_obj.get("ip_details", [])
                                
                                combined_graph_data = None
                                if isinstance(trace_info, dict) and trace_info.get("graph_data"):
                                    # 直接从 trace_info 获取（ip_trace 工具直调场景）
                                    latest_graph_data = trace_info.get("graph_data")
                                elif isinstance(ip_details, list) and ip_details:
                                    # brute_force 自动溯源场景：从 ip_details 中提取每个 IP 的 graph_data
                                    all_nodes = []
                                    all_edges = []
                                    ip_graph_count = 0
                                    for detail in ip_details:
                                        # app_logger.info(f"[DEBUG] Detail keys: {list(detail.keys())}, has_graph: {bool(detail.get('graph_data'))}")
                                        if isinstance(detail, dict):
                                            # 直接获取 graph_data (brute_force 返回结构)
                                            ip_gd = detail.get("graph_data")
                                            # 备用：如果嵌套在 trace_info 中 (某些特殊情况)
                                            if not ip_gd and detail.get("trace_info"):
                                                ip_gd = detail.get("trace_info", {}).get("graph_data")
                                            
                                            if isinstance(ip_gd, dict) and (ip_gd.get("nodes") or ip_gd.get("edges")):
                                                all_nodes.extend(ip_gd.get("nodes", []))
                                                all_edges.extend(ip_gd.get("edges", []))
                                                ip_graph_count += 1
                                    
                                    if all_nodes or all_edges:
                                        # 合并节点，并按状态优先级保留更严重状态。
                                        status_priority = {"": 0, "success": 1, "failed": 2, "blocked": 3}
                                        nodes_by_id = {}
                                        for node in all_nodes:
                                            nid = node.get("id", node.get("name", ""))
                                            if nid not in nodes_by_id:
                                                nodes_by_id[nid] = dict(node)
                                                continue
                                            current = nodes_by_id[nid]
                                            current_status = current.get("status", "")
                                            new_status = node.get("status", "")
                                            if status_priority.get(new_status, 0) > status_priority.get(current_status, 0):
                                                current["status"] = new_status
                                            for field in ("first_seen", "last_seen"):
                                                incoming = node.get(field, "")
                                                existing = current.get(field, "")
                                                if incoming and (not existing or (field == "first_seen" and incoming < existing) or (field == "last_seen" and incoming > existing)):
                                                    current[field] = incoming
                                        merged_nodes = list(nodes_by_id.values())

                                        # 合并边时必须包含 relation，且状态不能被先到的成功事件覆盖。
                                        edge_by_key = {}
                                        for edge in all_edges:
                                            ekey = (
                                                edge.get("source", ""),
                                                edge.get("target", ""),
                                                edge.get("relation", ""),
                                            )
                                            if ekey not in edge_by_key:
                                                edge_by_key[ekey] = dict(edge)
                                                continue
                                            current = edge_by_key[ekey]
                                            current_status = current.get("edge_status", "")
                                            new_status = edge.get("edge_status", "")
                                            if status_priority.get(new_status, 0) > status_priority.get(current_status, 0):
                                                current["edge_status"] = new_status
                                            incoming_ts = edge.get("timestamp", "")
                                            existing_ts = current.get("timestamp", "")
                                            if incoming_ts and (not existing_ts or incoming_ts < existing_ts):
                                                current["timestamp"] = incoming_ts
                                        merged_edges = list(edge_by_key.values())
                                        
                                        combined_graph_data = {
                                            "nodes": merged_nodes,
                                            "edges": merged_edges,
                                            "stats": {
                                                "node_count": len(merged_nodes),
                                                "edge_count": len(merged_edges),
                                                "ip_count": ip_graph_count,
                                                "type_distribution": {}
                                            }
                                        }
                                        # 合并各 IP 的 type_distribution
                                        for detail in ip_details:
                                            if isinstance(detail, dict):
                                                # 同样处理两种结构
                                                gd = detail.get("graph_data", {})
                                                if not gd: gd = detail.get("trace_info", {}).get("graph_data", {})
                                                
                                                ip_stats = gd.get("stats", {})
                                                ip_dist = ip_stats.get("type_distribution", {})
                                                for k, v in ip_dist.items():
                                                    combined_graph_data["stats"]["type_distribution"][k] = combined_graph_data["stats"]["type_distribution"].get(k, 0) + v
                                        
                                        # app_logger.info(f"[DEBUG] Extracted graph_data: nodes={len(merged_nodes)}, edges={len(merged_edges)}")
                                        latest_graph_data = combined_graph_data
                                    else:
                                        latest_graph_data = None
                                        yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
                                else:
                                    # 兜底：如果没有 ip_details，且 trace_info 中有 graph_data
                                    if isinstance(trace_info, dict) and trace_info.get("graph_data"):
                                        latest_graph_data = trace_info.get("graph_data")
                                        yield json.dumps({'tools': tools_use, 'graph_data': latest_graph_data}, ensure_ascii=False) + "\n\n"
                                    else:
                                        latest_graph_data = None
                                        yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
                            
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
                                yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
                            else:
                                yield json.dumps({'tools': [f"\n工具执行完成 (索引不存在): {output_obj.get('error', '查询失败')}"]}, ensure_ascii=False) + "\n\n"
                            # 不 return，继续循环处理 agent_finish 事件
                            continue

                        # HTTP 非 200 时，检查是否有 suggestion 字段（free_query 的 3 次重试兜底）
                        if http_status != 200:
                            if 'suggestion' in output_obj and output_obj['suggestion']:
                                # free_query 已经完成了 3 次重试，直接返回兜底建议
                                final_output = output_obj.get('error', '查询失败') + "\n\n" + output_obj['suggestion']
                                # 如果有 graph_data，一并推送
                                if latest_graph_data:
                                    yield json.dumps({'final_answer': final_output, 'graph_data': latest_graph_data}, ensure_ascii=False) + "\n\n"
                                else:
                                    yield json.dumps({'final_answer': final_output}, ensure_ascii=False) + "\n\n"
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
                                yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
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
                        
                        yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
                    except json.JSONDecodeError as e:
                        app_logger.info(f"JSON 解析失败：{e}")
                        app_logger.info(f"=== end ===\n")
                        tools_use = [
                            f"\n{str_lang['tool_executed']} ({str_lang['parse_failed']}): {output_str[:200]}..."
                        ]
                        yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
            
            elif status in (Status.start, Status.running):
                llm_token = data.get('llm_token', '')
                collected_answer += llm_token  # 收集所有通过 answer 输出的内容
                
                # 【修改】直接流式输出所有 answer，包括查询结果格式
                # 不再跳过 **查询结果** 等格式，让前端流式展示完整内容
                yield json.dumps({'answer': llm_token}, ensure_ascii=False) + "\n\n"
            
            elif status == Status.error:
                tools_use = [
                    f"\n {str_lang['tool_executed_failed']}",
                    f"{str_lang['error_msg']}: {data.get('error', str_lang['unknown_error'])}"
                ]
                yield json.dumps({'tools': tools_use}, ensure_ascii=False) + "\n\n"
            
            elif status == Status.agent_finish:
                final_answer = data.get("final_answer", "")
                index_check_steps = data.get("steps", [])
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
                    app_logger.info(f"[agent_finish] 从步骤信息构造 final_answer: {final_answer}")

                if final_answer:
                    if not collected_answer:
                        # 没有流式输出（early stop 场景）
                        should_push_final = True
                        reason = "early stop 无流式输出"
                    elif final_answer in collected_answer:
                        # final_answer 是流式的子集（重复了）
                        should_push_final = False
                        reason = "final_answer 已被流式包含"
                    elif collected_answer in final_answer:
                        # 流式是 final_answer 的子集（流式没输出完就 early stop）
                        should_push_final = True
                        reason = "流式片段，需补全"
                    else:
                        # 内容差异大（如流式是工具调用 JSON，final_answer 是真正答案）
                        should_push_final = True
                        reason = "内容不同"

                # 无论是否推送到 SSE，始终记录完整 final_answer
                app_logger.info(f"[agent_finish] 最终输出 (pushed={should_push_final}, reason={reason}, len={len(final_answer)}): {final_answer}")

                if should_push_final:
                    yield json.dumps({"final_answer": final_answer, "steps": index_check_steps}, ensure_ascii=False) + "\n\n"

                # 【修复】流完后只推一次 graph_data（精简版），作为"处理完成"信号
                if latest_trace_info or latest_graph_data:
                    slim_trace = {
                        "type": "graph_data",
                        "status": "success",
                        "ip_count": latest_trace_info.get("ip_count", 0) if latest_trace_info else 0,
                        "time_window": latest_trace_info.get("time_window", "") if latest_trace_info else "",
                        "graphs": []
                    }
                    if latest_trace_info and latest_trace_info.get("ip_details"):
                        for d in latest_trace_info["ip_details"]:
                            if isinstance(d, dict):
                                slim_trace["graphs"].append({
                                    "ip": d.get("ip", ""),
                                    "time_window": d.get("time_window", ""),
                                    "graph_data": d.get("graph_data", {})
                                })
                    elif latest_graph_data:
                        slim_trace["graphs"].append({
                            "ip": "",
                            "time_window": "",
                            "graph_data": latest_graph_data
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
                            {"type": "human", "data": {"content": user_input}},
                            {"type": "ai", "data": {"content": final_answer}}
                        ]
                        # 保留最近 10 轮对话（与内存缓存 k=5 对应，每轮 2 条消息）
                        new_history = new_history[-20:]
                        await mgr.save_session(session_id, new_history)
                    except Exception as e:
                        app_logger.warning(f"保存会话历史失败：{e}")
                # 退出循环
                break
        # 等待任务完成，释放资源
        await task

    # 返回流式响应
    app_logger.info(f"[响应] HTTP 200 | 正常流式响应 | session_id: {session_id}, user_input: {user_input}")
    return EventSourceResponse(agent_chat_iterator(user_input, scoped_session_id))


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
