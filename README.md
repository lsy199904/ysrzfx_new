# SIEM Agent 核心文件

基于 LangChain + FastAPI 的智能安全分析 Agent 服务，支持 ReAct 模式的工具调用、流式响应、多轮对话和日志压缩。

## 目录结构

```
core_files/
├── agent_chat.py          # FastAPI 主服务，Agent 核心逻辑
├── sever.py               # 流式回调处理器
├── custom_template.py     # 自定义 Prompt 模板和输出解析器
├── tools_select.py        # 工具注册和场景映射
├── redis_inspect.py       # Redis 检查工具
├── multi_args_tool.py     # 支持字典参数的工具包装类
├── tools/                 # 安全工具模块
│   ├── tool_base.py       # 工具基类和通用执行器
│   ├── common_config.py   # 通用配置（PPL 构建、ES 查询等）
│   ├── alert_rule.py      # 告警规则查询工具
│   ├── brute_force.py     # 暴力破解检测工具
│   ├── account_security_monitor.py  # 账户安全监控工具
│   ├── network_attack_detection.py  # 网络攻击检测工具
│   ├── system_security_monitor.py   # 系统安全监控工具
│   └── free_query.py      # 自由 PPL 查询工具
├── utils/                 # 工具类模块
│   ├── redis_manager.py   # Redis 管理器（会话、缓存、锁、限流）
│   ├── log_compressor.py  # 日志压缩器（字段压缩、智能聚合、语义筛选）
│   ├── circuit_breaker.py # 熔断器
│   └── request_timeout.py # 请求超时控制
└── test_*.py              # 测试脚本
```

## 功能架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SIEM Agent 架构                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │   用户界面    │───▶│  FastAPI 服务  │───▶│  LangChain   │               │
│  │  (Web/CLI)   │    │  (agent_chat)│    │   Agent      │               │
│  └──────────────┘    └──────────────┘    └──────────────┘               │
│                                              │                           │
│                              ┌───────────────┼───────────────┐           │
│                              ▼               ▼               ▼           │
│                       ┌──────────┐   ┌──────────┐   ┌──────────┐        │
│                       │ L1 场景工具 │   │ L2 自由查询 │   │  工具基座   │        │
│                       │          │   │          │   │          │        │
│                       │ - 暴力破解 │   │ - PPL 生成  │   │ - 缓存    │        │
│                       │ - 账户监控 │   │ - gid索引收窄 │ │ - 压缩    │        │
│                       │ - 网络攻击 │   │ - 3 次重试  │   │ - 步骤追踪 │        │
│                       │ - 系统监控 │   │          │   │          │        │
│                       │ - 告警规则 │   │          │   │          │        │
│                       └──────────┘   └──────────┘   └──────────┘        │
│                              │               │               │           │
│                              └───────────────┼───────────────┘           │
│                                              ▼                           │
│                    ┌──────────────────────────────────────────┐          │
│                    │              工具执行器                    │          │
│                    │  ┌────────────┐  ┌────────────┐          │          │
│                    │  │ Redis 缓存  │  │ ES 查询     │          │          │
│                    │  │ (5 分钟 TTL)│  │ (PPL 执行)  │          │          │
│                    │  └────────────┘  └────────────┘          │          │
│                    │         │              │                  │          │
│                    │         ▼              ▼                  │          │
│                    │  ┌─────────────────────────────────┐     │          │
│                    │  │        日志压缩器                │     │          │
│                    │  │  字段压缩 → 智能聚合 → 语义筛选   │     │          │
│                    │  └─────────────────────────────────┘     │          │
│                    └──────────────────────────────────────────┘          │
│                                              │                           │
│                              ┌───────────────┼───────────────┐           │
│                              ▼               ▼               ▼           │
│                       ┌──────────┐   ┌──────────┐   ┌──────────┐        │
│                       │  Redis   │   │ElasticS. │   │  LLM     │        │
│                       │  (会话)  │   │  (日志)  │   │ (Qwen3)  │        │
│                       └──────────┘   └──────────┘   └──────────┘        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 核心功能

### 1. Agent 服务特性

- **ReAct 模式**：思考 → 行动 → 观察循环
- **实例隔离**：每个请求独立的工具和会话
- **流式响应**：SSE 实时推送
- **多轮对话**：滑动窗口记忆（基于 Redis）
- **Token 预算控制**：自动截断过长历史
- **错误处理**：自动处理解析错误

### 2. 安全工具列表
。
| 工具名称 | 层级 | 功能描述 |
|---------|------|---------|
| `alert_rule_request` | L1 | 告警规则查询与分析 |
| `brute_force_request` | L1 | 暴力破解攻击检测（查询 Fortigate 防火墙登录失败记录） |
| `account_security_monitor_request` | L1 | 账户安全监控（账户创建/删除/权限变更） |
| `network_attack_request` | L1 | 网络攻击检测（IPS 入侵检测） |
| `system_security_request` | L1 | 系统安全监控（设备重启/关机/配置变更） |
| `free_query_request` | L2 | 自由 PPL 查询（支持自定义日志查询，带 3 次重试机制） |

### 3. 工具基座功能

- **Redis 缓存**：工具调用结果自动缓存（5 分钟 TTL）
- **日志压缩**：
  - 字段压缩（超过 20 字段时触发）
  - 智能聚合（按攻击源 IP 分组统计）
  - 语义筛选（BERT + 余弦相似度）
- **步骤追踪**：记录查询流程，便于调试
- **统计摘要**：始终生成原始数据统计摘要，供 LLM 参考

### 4. Redis 管理器功能

- **会话管理**：会话历史、场景状态、用户会话列表
- **工具缓存**：工具调用结果缓存
- **查询缓存**：PPL 查询结果缓存
- **分布式锁**：并发控制
- **限流控制**：API 限流
- **消息队列**：异步任务处理

### 5. 日志压缩器功能

| 压缩阶段 | 触发条件 | 压缩策略 |
|---------|---------|---------|
| 字段压缩 | 字段数 > 20 | 保留关键字段（时间、IP、用户、事件等） |
| 智能聚合 | 记录数 > 3 且问题含统计关键词 | 按源 IP 分组统计 |
| 语义筛选 | Token 数 > 3000 | BERT + 余弦相似度保留 Top K |

## 当前进展

### 已完成功能

- [x] **基础架构搭建**
  - [x] FastAPI 服务框架
  - [x] LangChain Agent 集成
  - [x] SSE 流式响应
  - [x] Redis 会话管理

- [x] **L1 场景化工具（5 个）**
  - [x] 暴力破解检测工具
  - [x] 账户安全监控工具
  - [x] 网络攻击检测工具
  - [x] 系统安全监控工具
  - [x] 告警规则查询工具

- [x] **L2 自由查询工具**
  - [x] LLM 生成 PPL 查询
  - [x] gid 索引收窄与时间字段过滤
  - [x] 3 次重试机制
  - [x] 失败后 L1 场景引导

- [x] **日志压缩模块**
  - [x] 字段压缩
  - [x] 智能聚合
  - [x] 语义筛选（BERT）
  - [x] 统计摘要生成

- [x] **工具基座模块**
  - [x] 统一工具执行器
  - [x] Redis 缓存管理
  - [x] 步骤追踪
  - [x] 异常处理

- [x] **Token 预算控制**
  - [x] 动态历史截断
  - [x] Token 估算函数

- [x] **容器化部署**
  - [x] Docker 镜像构建
  - [x] 端口映射配置
  - [x] 目录挂载配置

### 测试覆盖

| 测试脚本 | 覆盖工具 | 状态 |
|---------|---------|------|
| `test_brute.py` | 暴力破解检测 | ✅ 已验证 |
| `test_account.py` | 账户安全监控 | ✅ 已验证 |
| `test_network.py` | 网络攻击检测 | ✅ 已验证 |
| `test_system.py` | 系统安全监控 | ✅ 已验证 |
| `test_alert.py` | 告警规则查询 | ✅ 已验证 |
| `test_free_query.py` | 自由 PPL 查询 | ✅ 已验证 |

## 待优化点

1. **框架问答限制底层修改**
   - 当前限制：只让提问多长时间范围内的数据
   - 后续计划：根据产品意见进行迭代调整
   - 目的：防止集群拉爆，保护后端服务稳定性

2. **压缩策略优化**
   - 当前问题：测试环境看到的数据有限，压缩策略可能不够完善
   - 优化方向：根据真实生产环境数据调整压缩阈值和策略
   - 需要验证：字段压缩、智能聚合、语义筛选的实际效果

3. **大模型算力问题优化**
   - 当前问题：所选模型（Qwen3-32B）因算力限制，32K 输出偶尔截断
   - 影响：长回答可能被截断，信息不完整
   - 解决方向：升级算力资源

4. **场景 PPL 模板确认**
   - 需要确认：现有 L1 场景 PPL 模板是否需要调整
   - 需要补齐：检查是否有遗漏的场景 PPL 模板
   - 待办事项：
     - 暴力破解场景模板确认
     - 账户安全监控场景模板确认
     - 网络攻击检测场景模板确认
     - 系统安全监控场景模板确认
     - 告警规则查询场景模板确认

## 快速开始

### 部署架构

```
本地主机 → 跳板机 (203.85.9.162:58001) → 目标主机 (192.168.101.110)
```

### 容器配置

| 项目 | 配置 |
|------|------|
| 容器名称 | `siem-agent` |
| Python 版本 | 3.11.14 |
| 镜像名称 | siem-python311-full:latest |

### 端口映射（宿主机:容器）

| 宿主机端口 | 容器端口 | 说明 |
|-----------|---------|------|
| 5050 | 8000 | Agent Chat 服务 |
| 5051 | 8001 | 预留服务端口 1 |
| 5052 | 8002 | 预留服务端口 2 |
| 5053 | 8003 | 预留服务端口 3 |
| 5054 | 8004 | 预留服务端口 4 |
| 6379 | 6379 | Redis 服务 |

### 目录挂载

| 宿主机目录 | 容器目录 | 说明 |
|-----------|---------|------|
| /home/sylvanli/ysrzfx | /app | 代码和项目目录 |
| /home/sylvanli/ysrzfx/code/core_files | /app/core_files | 核心代码目录 |

### 部署步骤

#### 步骤 1：打包 Docker 镜像和代码

```bash
# 进入项目目录
cd /home/sylvanli/ysrzfx

# 创建打包目录
mkdir -p enviroment

# 保存容器为镜像
docker commit siem siem-python311-full:latest

# 导出镜像并压缩
docker save siem-python311-full:latest > enviroment/siem-python311-full.tar
gzip enviroment/siem-python311-full.tar

# 打包代码目录（包含虚拟环境、数据、模型等）
tar -czf enviroment/ysrzfx-full.tar.gz \
  code/ \
  data/ \
  hf_cache/ \
  dump.rdb \
  ysrzfx_new/ \
  run.sh \
  Dockerfile \
  README.md

# 查看打包结果
ls -lh enviroment/
```

#### 步骤 2：传输到目标主机

通过跳板机传输到目标主机 (192.168.101.110)：
```bash
scp -P 22 /home/sylvanli/SIEM-YSRZFX/siem-python311.tar.gz sylvanli@192.168.101.110:/home/sylvanli/ysrzfx/
scp -P 22 /home/sylvanli/SIEM-YSRZFX/ysrzfx-code.tar.gz sylvanli@192.168.101.110:/home/sylvanli/ysrzfx/
```

#### 步骤 3：加载 Docker 镜像

在目标主机执行：
```bash
# 加载镜像
docker load < siem-python311-full.tar.gz

# 验证镜像
docker images | grep siem-python311-full
```

#### 步骤 4：启动容器

```bash
# 停止并删除已存在的容器（如果有）
docker rm -f siem-agent 2>/dev/null

# 启动容器
docker run -d \
  --name siem-agent \
  --restart always \
  -p 5050:8000 \
  -p 5051:8001 \
  -p 5052:8002 \
  -p 5053:8003 \
  -p 5054:8004 \
  -p 6379:6379 \
  -v /home/sylvanli/ysrzfx:/app \
  -w /app \
  siem-python311-full:latest \
  bash -c "
    # 启动 Redis 服务
    redis-server --daemonize yes
    sleep 1
    echo 'Redis 服务已启动'
    
    # 激活虚拟环境
    source /app/ysrzfx_new/bin/activate
    
    # 启动后端服务
    python /app/core_files/agent_chat.py
  "
```

#### 步骤 5：验证服务

```bash
# 检查容器状态
docker ps | grep siem-agent
```

### 配置说明

#### 环境变量配置（.env）

复制 `.env.example` 为 `.env`，根据环境填写配置。应用会自动加载项目根目录的 `.env`，
进程环境变量优先级高于 `.env`。大模型、ES 账号密码、告警服务 SSO 密钥等配置不再写入业务代码。

```bash
cp .env.example .env

# 常用配置示例
LLM_BASE_URL=http://your-llm-service:18080
LLM_MODEL=Qwen/Qwen3-32B
ES_HOST=your-es-host
ES_AUTH_USER=your-es-user
ES_AUTH_PASSWORD=your-es-password
ALERT_SSO_APP_ID=your-app-id
ALERT_SSO_SECRET_KEY=your-secret
```

#### 索引组合配置（index_config.yaml）

索引格式为 `log_g{gid}_{vendor}_{product}`。在 `index_config.yaml` 中维护允许查询的
厂商和产品组合；增加组合后，系统会自动为每个 gid 拼接并探测对应索引。

```yaml
index_combinations:
  - vendor: fortinet
    product: fortigate
  - vendor: fortinet
    product: sase
```

### 测试接口

```bash
# 使用测试脚本
python test_free_query.py
python test_brute.py
python test_network.py
python test_account.py
python test_system.py
python test_alert.py
```
curl -X POST http://10.180.158.23:5050/agentchat \
  -H "Content-Type: application/json" \
  -d '{"session_id": "session_001", "user_input": "最近24小时有没有暴力破解攻击"}' \



## 工具调用流程

```
用户提问
   ↓
Agent 思考（LLM 分析意图）
   ↓
选择工具（从 6 个安全工具中）
   ↓
提取参数（时间、IP、用户等）
   ↓
执行工具（调用 ES 查询）
   ↓
日志压缩（按需要）
   ↓
返回结果（JSON + 步骤信息）
   ↓
LLM 总结 → 最终答案
```

## 相关文档

- [API 文档](./API_DOCUMENTATION.md) - 接口调用详细说明
- [部署指南](./DEPLOYMENT.md) - 容器化部署步骤# ysrzfx_new
# ysrzfx_new
# ysrzfx_new
