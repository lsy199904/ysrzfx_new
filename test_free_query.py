import json
import requests
import time

def call_agent_stream_api(session_id, user_input):
    start_time = time.time()
    url = "http://127.0.0.1:8000/agentchat"
    headers = {"Content-Type": "application/json"}
    payload = {
        "session_id": session_id,
        "user_input": user_input.strip()
    }

    with requests.post(url, json=payload, headers=headers, stream=True) as response:
        if response.status_code != 200:
            print(f"接口请求失败，状态码：{response.status_code}")
            return

        # 【修复】chunk_size=1 避免 requests 库 buffering 导致最后几个 chunk 丢失
        for line in response.iter_lines(decode_unicode=True, chunk_size=1):
            if line:
                # SSE 格式：data: {"answer": "..."}
                # 移除 "data: " 前缀
                if line.startswith("data: "):
                    sse_data = line[6:].strip()
                else:
                    sse_data = line.strip()
                if sse_data:
                    try:
                        data = json.loads(sse_data)

                        if "answer" in data:
                            print(data["answer"], end="", flush=True)

                        elif "tools" in data:
                            print("\n")
                            print("─" * 50)
                            for item in data["tools"]:
                                print(item)
                            print("─" * 50)

                        # 【修复】先判断 graph_data（新格式，type=graph_data 含精简的 graphs 数组）
                        elif data.get("type") == "graph_data":
                            print("\n" + "="*50)
                            print("【图谱数据 graph_data】")
                            print(f"  status: {data.get('status', '')}")
                            print(f"  ip_count: {data.get('ip_count', 0)}")
                            print(f"  time_window: {data.get('time_window', '')}")
                            graphs = data.get("graphs", [])
                            print(f"  graphs: 共 {len(graphs)} 个")
                            for i, g in enumerate(graphs, 1):
                                if isinstance(g, dict):
                                    print(f"    ┌── [{i}] IP={g.get('ip', '')}  time_window={g.get('time_window', '')}")
                                    gd = g.get("graph_data", {})
                                    if isinstance(gd, dict):
                                        print(f"    │   nodes: {len(gd.get('nodes', []))} 个, edges: {len(gd.get('edges', []))} 条")
                                        for n in gd.get("nodes", []):
                                            print(f"    │     • {n.get('name', '')} ({n.get('type', '')})")
                                        for e in gd.get("edges", []):
                                            print(f"    │     • {e.get('source','')} --{e.get('relation','')}--> {e.get('target','')}")
                                    print(f"    └──")

                        # 兼容旧的 trace_info 格式
                        elif "trace_info" in data:
                            print("\n" + "="*50)
                            print("【溯源数据 trace_info】(旧格式)")
                            ti = data["trace_info"]
                            print(f"  长度: {len(json.dumps(ti, ensure_ascii=False))} 字符")

                        elif "final_answer" in data:
                            print("\n" + "="*50)
                            print("最终答案：")
                            print(data["final_answer"])
                    except json.JSONDecodeError:
                        continue

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n接口请求总耗时：{elapsed_time:.3f}秒")



def call_agent_stream_api_with_auth(session_id, user_input, login_account="test", is_admin=False, allowed_gids=None):
    """
    调用 agent_chat 接口，支持传入 auth 参数（gid 权限控制）
    
    Args:
        session_id: 会话 ID
        user_input: 用户问题
        login_account: 登录账号
        is_admin: 是否管理员
        allowed_gids: 允许查询的 gid 列表，不传则默认为 ["12345", "19936"]
    """
    start_time = time.time()
    url = "http://127.0.0.1:8000/agentchat"
    headers = {"Content-Type": "application/json"}
    payload = {
        "session_id": session_id,
        "user_input": user_input.strip(),
        "login_account": login_account,
        "is_admin": is_admin,
        "allowed_gids": allowed_gids
    }

    with requests.post(url, json=payload, headers=headers, stream=True) as response:
        if response.status_code != 200:
            print(f"接口请求失败，状态码：{response.status_code}")
            return

        # 【修复】chunk_size=1 避免 requests 库 buffering 导致最后几个 chunk 丢失
        for line in response.iter_lines(decode_unicode=True, chunk_size=1):
            if line:
                if line.startswith("data: "):
                    sse_data = line[6:].strip()
                else:
                    sse_data = line.strip()
                if sse_data:
                    try:
                        data = json.loads(sse_data)
                        if "answer" in data:
                            print(data["answer"], end="", flush=True)
                        elif "tools" in data:
                            print("\n")
                            print("─" * 50)
                            for item in data["tools"]:
                                print(item)
                            print("─" * 50)

                        # 【修复】先判断 trace_info（因为它也包含 final_answer 字段）
                        elif "trace_info" in data:
                            print("\n" + "="*50)
                            print("【溯源数据 trace_info】")
                            ti = data["trace_info"]
                            if isinstance(ti, dict):
                                for k, v in ti.items():
                                    if k == "ip_details":
                                        if isinstance(v, list):
                                            print(f"  {k}: 共 {len(v)} 个 IP")
                                            for i, ip_obj in enumerate(v, 1):
                                                if isinstance(ip_obj, dict):
                                                    ip = ip_obj.get("ip") or ip_obj.get("srcip") or ip_obj.get("source_ip", f"IP_{i}")
                                                    print(f"    ┌── [{i}] {ip}")
                                                    # 完整展开每个 IP 的所有字段
                                                    ip_json = json.dumps(ip_obj, ensure_ascii=False, indent=4)
                                                    for line in ip_json.split("\n"):
                                                        print(f"    │   {line}")
                                                    print(f"    └──")
                                                else:
                                                    print(f"    [{i}] {ip_obj}")
                                        else:
                                            print(f"  {k}: {v}")
                                    else:
                                        s = json.dumps(v, ensure_ascii=False) if not isinstance(v, (str, int, float, bool)) else v
                                        print(f"  {k}: {s}")
                            else:

                                print(f"  {ti}")
                            if data.get("graph_data"):
                                print(f"  graph_data: <已包含，{len(json.dumps(data['graph_data'], ensure_ascii=False))} 字符>")

                        elif "final_answer" in data:
                            print("\n" + "="*50)
                            print("最终答案：")
                            print(data["final_answer"])
                    except json.JSONDecodeError:
                        continue

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\n接口请求总耗时：{elapsed_time:.3f}秒")


if __name__ == "__main__":
    test_session_id = "free_query_test_004"
    # ===========================================
    # 【gid 权限控制测试】新增测试
    # ===========================================
    print("=" * 60)
    print("【测试 1】在白名单内的 gid 查询（应该成功）")
    print("允许查询的 gid: 12345, 19936 | 请求查询 gid: 19936")
    print("=" * 60)
    call_agent_stream_api_with_auth(
        session_id=f"{test_session_id}_gid_auth_1",
        user_input="2026年gid19934的3月26日有哪些暴力破解记录",
        # user_input="2026年gid19936的3月26日有哪些暴力破解记录",
        # user_input="查询2026年3月26日gid为19936的网络攻击记录",
        # user_input = "查询2026年3月26日的wang_wu的账户变更日志" ,
        # user_input = "查询2026年3月26日的admin的系统安全监控记录",
        login_account="test_user",
        is_admin=False,
        allowed_gids=["15768", "19936","19934"]
    )
    
    # print("\n\n" + "=" * 60)
    # print("【测试 2】不在白名单内的 gid 查询（应该被拦截，返回 403）")
    # print("允许查询的 gid: 12345, 19936 | 请求查询 gid: 99999")
    # print("=" * 60)
    # call_agent_stream_api_with_auth(
    #     session_id=f"{test_session_id}_gid_auth_2",
    #     user_input="查询 gid 99999 的暴力破解日志",
    #     login_account="test_user",
    #     is_admin=False,
    #     allowed_gids=["12345", "19936"]
    # )
    
    # print("\n\n" + "=" * 60)
    # print("【测试 3】不传 gid 的受限用户查询（应该自动注入白名单 or 条件）")
    # print("允许查询的 gid: 12345, 19936 | 未指定 gid")
    # print("=" * 60)
    # call_agent_stream_api_with_auth(
    #     session_id=f"{test_session_id}_gid_auth_3",
    #     user_input="查询2026年3月26日的gid65789的暴力破解日志",
    #     login_account="test_user",
    #     is_admin=False,
    #     allowed_gids=["12345", "19936","65789"]
    # )
    
    # print("\n\n" + "=" * 60)
    # print("【测试 4】管理员查询（应该无限制）")
    # print("is_admin=True | allowed_gids=None")
    # print("=" * 60)
    # call_agent_stream_api_with_auth(
    #     session_id=f"{test_session_id}_gid_auth_4",
    #     user_input="查询2026年3月26日的暴力破解日志",
    #     login_account="admin",
    #     is_admin=True,
    #     allowed_gids=None
    # )
    
    # ===========================================
    #问答提问
    # ===========================================
    # test_input = "你好，请介绍一下你自己"
    # test_input = "在2025年1月到2025年3月的告警，请详细分析并以表格形式输出结果"
    # ===========================================
    # L1 场景化问题测试
    # ===========================================
    # -------------------------------------------
    #### 暴力破解类
    # -------------------------------------------
    # test_input = "今天有哪些暴力破解攻击记录？"
    # test_input = "最近24小时的暴力破解攻击情况" 
    # test_input = "查询近7天gid12345的暴力破解日志" 
    # test_input = "查询2026年5月8日8点~22点之间的暴力破解日志" 
    # test_input = "2026年3月26日有哪些暴力破解记录" 
    # test_input = "显示2026年4月20日来自IP 192.168.1.100的暴力破解尝试" 

    # -------------------------------------------
    ####系统安全监控记录（两个环境均能测通PPL模板，测试环境没有数据，正式环境有）
    # -------------------------------------------
     #日期类
    # test_input = "今天有哪些系统安全监控记录？"
    # test_input = "最近24小时的系统安全监控记录" 
    # test_input = "查询近7天的系统安全监控日志" 
    # test_input = "查询2026年3月26日的系统安全监控记录" 
    # #用户类检索
    # test_input = "查询用户admin的系统安全监控记录"
    # test_input = "显示来自IP 192.168.1.100的系统安全监控记录" 
    # test_input = "显示2026年4月20日来自IP 192.168.1.100的用户admin的系统安全监控记录" 

    # -------------------------------------------
    ####账户变更（当前测试环境、研发环境查询均无数据（PPL模板与告警规则都没有数据））
    # -------------------------------------------
    # test_input = "今天有哪些账户变更记录？"
    # test_input = "最近24小时的账户变更情况" 
    # test_input = "查询近7天的账户变更日志" 
    # test_input = "查询2026年3月26日的账户变更日志" 
    # #用户类检索
    # test_input = "查询用户admin的账户变更" 
    # #ip类检索
    # test_input = "显示来自IP 192.168.1.100的账户变更" 
    # test_input = "显示2026年4月20日来自IP 192.168.1.100的账户变更" 

    # -------------------------------------------
    ####网络攻击记录（当前测试环境、研发环境查询均无数据（PPL模板与告警规则都没有数据））
    # -------------------------------------------
    #日期类
    # test_input = "今天有哪些网络攻击记录？"
    # test_input = "最近24小时的网络攻击记录" 
    # test_input = "查询近7天的网络攻击日志" 
    # test_input = "查询2026年3月26日的网络攻击记录" 
    # #用户类检索
    # test_input = "查询用户admin的网络攻击记录" 
    # #ip类检索
    # test_input = "显示来自IP 192.168.1.100的网络攻击记录" 
    # test_input = "显示2026年4月20日来自IP 192.168.1.100的用户admin的网络攻击记录" 
    # ===========================================
    # L2 自由查询问题测试
    # ===========================================
    # test_input = "查看2026年4月26日gid=12345的VPN相关记录"
    # test_input = "查看2026年4月26日gid=12345的设备相关异常记录"
    # test_input = "gid为12345的2026年4月26日有多少次登录登出记录"
    # test_input = "查找所有gid为12345的来自 192.168.1.100 的日志"
    # test_input = "当前原始日志有多少条"

    # ===========================================
    #测试数据问题
    # ===========================================
    # test_input = "2026年3月26日有哪些暴力破解记录"
    # test_input = "2026年3月26日Ip为10.180.36.7的有哪些暴力破解记录"
    # test_input = "2026年3月26日用户chen_liu有哪些暴力破解记录"
    # test_input = "2026年3月26日gid为19936用户zhang_san有哪些暴力破解记录"

    # test_input = "查询2026年3月26日gid为15768的网络攻击记录" 
    # test_input = "查询2026年3月26日gid为15768的攻击ip为192.168.1.1的网络攻击记录" 
    # test_input = "查询2026年3月26日gid为19936-irdit的用户li的攻击ip为103.45.67.91的网络攻击记录" 

    # test_input = "查询2026年3月26日的wang_wu的账户变更日志" 
    # test_input = "查询2026年3月26日5点-11点的wang_wu的10.180.60.20的账户变更日志" 

    # test_input = "查询2026年3月26日的admin的系统安全监控记录" 
    # test_input = "查询2026年3月26日的系统安全监控记录" 
    # test_input = "你好" 



    # print(f"测试问题：{test_input}")
    # print("-" * 50)
    
    # try:
    #     call_agent_stream_api(test_session_id, test_input)
    # except requests.exceptions.ConnectionError:
    #     print("无法连接到后端服务，请检查：1. 服务是否启动 2. 地址和端口是否正确")
    # except Exception as e:
    #     print(f"调用异常：{str(e)}")