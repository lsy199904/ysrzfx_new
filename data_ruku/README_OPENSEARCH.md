# OpenSearch 导入

`ingest_opensearch.py` 会读取 JSON 数组，创建索引
`log_g19936_fortinet_fortigate`，然后使用 OpenSearch Python 客户端的 bulk API
批量写入文档。

## 安装

```bash
python3 -m pip install -r requirements-opensearch.txt
```

## 配置连接

```bash
export OPENSEARCH_URL="https://192.168.100.45:9200"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="2025&SieMYbs2%w21639"
export OPENSEARCH_VERIFY_CERTS="true"
# 使用自建 CA 时填写 PEM 文件路径；公有 CA 可不设置
export OPENSEARCH_CA_CERTS="true"
```

如果是本地自签名证书测试环境，可临时设置：

```bash
export OPENSEARCH_VERIFY_CERTS="false"
```

## 导入

默认读取：
`/Users/1272722735qq.com/Downloads/brute_force_samples.json`

```bash
python3 ingest_opensearch.py
```

也可以显式传入文件：

```bash
python3 ingest_opensearch.py /path/to/brute_force_samples.json
```

如果需要清空并重建同名索引：

```bash
python3 ingest_opensearch.py --recreate
```
