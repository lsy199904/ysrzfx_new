# FortiGate Pipeline 样例入库

`data_ruku` 中的四个 `*_samples.json` 是给现网
`fortinet_fortigate_default` Pipeline 使用的输入文件。每条文档的核心是
`message` 字段，内容必须是 FortiGate 的 `key=value` Syslog。Pipeline 会从
`message` 解析并生成 `fortinet.firewall.*`、ECS、用户、IP、策略等字段。

## 文件说明

```text
data_ruku/
├── account_security_samples.json   # 账户变更，515 条
├── brute_force_samples.json        # 暴力破解，500 条
├── network_attack_samples.json     # 网络攻击，500 条
├── system_security_samples.json    # 系统安全，500 条
├── raw_samples/                    # 转换前原始样例，仅作追溯
├── prepare_pipeline_samples.py     # 生成 Pipeline 输入格式
├── ingest_opensearch.py            # 批量入库
└── requirements-opensearch.txt
```

`raw_samples` 中的文件不是直接入库文件。修改原始样例后，重新执行：

```bash
python3 data_ruku/prepare_pipeline_samples.py
```

## 配置连接

入库脚本支持项目 `.env` 使用的 `ES_*` 变量，也支持独立的
`OPENSEARCH_*` 变量。推荐在 Shell 中读取密码，避免特殊字符被解释：

```bash
export ES_SCHEME=https
export ES_HOST=192.168.100.45
export ES_PORT=9200
export ES_USER='your_user'
read -rsp 'OpenSearch password: ' ES_PASSWORD
echo
export ES_VERIFY_SSL=false
```

也可以使用：

```bash
export OPENSEARCH_URL='https://192.168.100.45:9200'
export OPENSEARCH_USERNAME='your_user'
read -rsp 'OpenSearch password: ' OPENSEARCH_PASSWORD
echo
export OPENSEARCH_VERIFY_CERTS=false
```

## 导入四个场景

确认已删除旧 Data Stream 后，在项目根目录执行：

```bash
python3 data_ruku/ingest_opensearch.py --all \
  --index log_g19936_fortinet_fortigate
```

脚本不会显式覆盖 Pipeline。目标名称匹配现有 Data Stream 模板时，OpenSearch
会自动使用 `fortinet_fortigate_default` 默认 Pipeline。

如需单独导入一个场景：

```bash
python3 data_ruku/ingest_opensearch.py \
  data_ruku/brute_force_samples.json \
  --index log_g19936_fortinet_fortigate
```

## 入库后检查

先检查总量：

```text
search source=`log_g19936_fortinet_fortigate`
| stats count()
```

再检查暴力破解字段：

```text
search source=`log_g19936_fortinet_fortigate`
| where @gid = '19936' and event.action = 'login'
| fields @timestamp, source.user.name, event.action, event.reason,
         fortinet.firewall.subtype, fortinet.firewall.status, observer.name
| head 20
```

期望看到 `subtype=system`、`status=failed`。如果字段为空，优先检查入库文档
的 `message` 是否仍然是完整的 FortiGate KV Syslog。
