from tools.network_attack_detection import network_attack_request

# 测试网络攻击查询 - 使用 IP 过滤
result = network_attack_request(
    user_problem="查询2026年3月26日gid为19936的用户li的攻击ip为202.76.24.50的网络攻击记录",
    start_time="2026-03-26",
    end_time="2026-03-26",
    filter_ip="202.76.24.50",
    filter_user="li",
    gid="19936"
)

print("\n" + "="*60)
print("测试结果:")
print("="*60)
import json
data = json.loads(result)
print(f"HTTP 状态码: {data.get('http_status')}")
print(f"错误信息: {data.get('error', '无')}")
print(f"记录数: {data.get('count')}")
if data.get('steps'):
    for step in data['steps']:
        print(f"\n步骤 {step['step']}: {step['title']}")
        print(f"详情: {step['detail'][:200]}")
