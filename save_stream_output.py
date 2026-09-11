# -*- coding: utf-8 -*-
"""
保存 Agent 接口流式输出到文件

功能：
1. 调用 Agent 接口获取 SSE 流式响应
2. 保存原始 JSONL 格式（每行一个 JSON 对象）
3. 生成解析后的 txt 文件

输出参数说明：
- answer: LLM 流式生成的思考过程（token by token）
- tools: 工具调用详情，包含步骤（step、title、detail、is_code）
- final_answer: Agent 最终归纳的答案
- error: 错误信息（当发生错误时）

使用方法：
1. 修改下方的 test_input 问题
2. 运行脚本：python save_stream_output.py
3. 如需英文版本，修改问题为英文后再次运行
"""
import json
import requests
from config import APP_HOST, APP_PORT
import time
from datetime import datetime


def call_and_save_stream_output(session_id, user_input, output_dir="./output", lang="zh"):
    """
    调用 Agent 接口并保存流式输出到文件
    
    Args:
        session_id: 会话 ID
        user_input: 用户输入的问题
        output_dir: 输出目录
        lang: 语言标识（zh 或 en）
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    start_time = time.time()
    url = f"http://{APP_HOST}:{APP_PORT}/agentchat"
    headers = {"Content-Type": "application/json"}
    payload = {
        "session_id": session_id,
        "user_input": user_input.strip()
    }
    
    # 生成带时间戳和语言标识的文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_file = os.path.join(output_dir, f"stream_{timestamp}_{lang}.jsonl")
    txt_file = os.path.join(output_dir, f"stream_{timestamp}_{lang}.txt")
    
    # 收集所有 SSE 数据
    sse_records = []
    
    # 语言相关配置
    if lang == "en":
        title = "Agent Stream Output Analysis"
        labels = {
            "session_id": "Session ID",
            "user_input": "User Input",
            "time": "Timestamp",
            "elapsed": "Elapsed Time",
            "records": "SSE Records",
            "thinking": "Thinking Process",
            "tools": "Tool Calls",
            "final": "Final Answer",
            "error": "Error",
            "complete": "Analysis Complete"
        }
    else:
        title = "Agent 流式输出解析"
        labels = {
            "session_id": "会话 ID",
            "user_input": "用户输入",
            "time": "时间",
            "elapsed": "总耗时",
            "records": "SSE 记录数",
            "thinking": "思考过程",
            "tools": "工具调用",
            "final": "最终答案",
            "error": "错误信息",
            "complete": "解析完成"
        }
    
    print(f"开始调用接口 ({lang.upper()})...")
    print(f"问题：{user_input}")
    print("-" * 50)
    
    with requests.post(url, json=payload, headers=headers, stream=True) as response:
        if response.status_code != 200:
            print(f"接口请求失败，状态码：{response.status_code}")
            return None
        
        # 打开文件准备写入
        with open(jsonl_file, 'w', encoding='utf-8') as f_jsonl:
            
            for line in response.iter_lines(decode_unicode=True):
                if line:
                    sse_data = line.lstrip("data: ").strip()
                    if sse_data:
                        try:
                            data = json.loads(sse_data)
                            
                            # 保存原始 JSON 到 jsonl 文件
                            f_jsonl.write(json.dumps(data, ensure_ascii=False) + "\n")
                            sse_records.append(data)
                            
                            # 控制台输出
                            if "answer" in data:
                                print(data["answer"], end="", flush=True)
                            
                            elif "tools" in data:
                                print("\n")
                                print("─" * 50)
                                for item in data["tools"]:
                                    print(item)
                                print("─" * 50)
                            
                            elif "final_answer" in data:
                                print("\n" + "="*50)
                                if lang == "en":
                                    print("Final Answer:")
                                else:
                                    print("最终答案：")
                                print(data["final_answer"])
                            
                            elif "error" in data:
                                if lang == "en":
                                    print(f"\nError: {data['error']}")
                                else:
                                    print(f"\n错误：{data['error']}")
                                
                        except json.JSONDecodeError:
                            continue
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # 拼接完整内容
    answer_content = ""
    tools_content = []
    final_answer_content = ""
    error_content = None
    
    for record in sse_records:
        if "answer" in record:
            answer_content += record["answer"]
        elif "tools" in record:
            tools_content.append(record["tools"])
        elif "final_answer" in record:
            final_answer_content = record["final_answer"]
        elif "error" in record:
            error_content = record["error"]
    
    # 生成解析文件
    with open(txt_file, 'w', encoding='utf-8') as f:
        # 头部信息
        f.write("=" * 60 + "\n")
        f.write(f"{title} ({lang.upper()})\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"{labels['session_id']}: {session_id}\n")
        f.write(f"{labels['user_input']}: {user_input}\n")
        f.write(f"{labels['time']}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{labels['elapsed']}: {elapsed_time:.3f}秒\n")
        f.write(f"{labels['records']}: {len(sse_records)}条\n\n")
        
        # 思考过程
        f.write("-" * 60 + "\n")
        if lang == "en":
            f.write(f"【{labels['thinking']}】(answer field concatenated)\n")
        else:
            f.write(f"【{labels['thinking']}】(answer 字段拼接)\n")
        f.write("-" * 60 + "\n")
        f.write(f"{answer_content}\n\n")
        
        # 工具调用
        if tools_content:
            f.write("-" * 60 + "\n")
            if lang == "en":
                f.write(f"【{labels['tools']}】(tools field)\n")
            else:
                f.write(f"【{labels['tools']}】(tools 字段)\n")
            f.write("-" * 60 + "\n")
            for tool_list in tools_content:
                for item in tool_list:
                    f.write(f"{item}\n")
            f.write("\n")
        
        # 最终答案
        if final_answer_content:
            f.write("-" * 60 + "\n")
            if lang == "en":
                f.write(f"【{labels['final']}】(final_answer field)\n")
            else:
                f.write(f"【{labels['final']}】(final_answer 字段)\n")
            f.write("-" * 60 + "\n")
            f.write(f"{final_answer_content}\n\n")
        
        # 错误信息
        if error_content:
            f.write("-" * 60 + "\n")
            if lang == "en":
                f.write(f"【{labels['error']}】(error field)\n")
            else:
                f.write(f"【{labels['error']}】(error 字段)\n")
            f.write("-" * 60 + "\n")
            f.write(f"{error_content}\n\n")
        
        # 尾部
        f.write("=" * 60 + "\n")
        f.write(f"{labels['complete']}\n")
        f.write("=" * 60 + "\n")
    
    print(f"{'='*60}")
    print(f"接口请求总耗时：{elapsed_time:.3f}秒")
    print(f"已保存到：")
    print(f"  原始数据：{jsonl_file}")
    print(f"  解析文件：{txt_file}")
    
    return {
        "jsonl_file": jsonl_file,
        "txt_file": txt_file,
        "records_count": len(sse_records),
        "elapsed_time": elapsed_time
    }


if __name__ == "__main__":
    # ===========================================
    # 配置测试参数
    # ===========================================
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # ===========================================
    # 修改这里的 lang 来选择语言：
    # - "zh" = 中文
    # - "en" = 英文
    # ===========================================
    lang = "en"  # 或 "en"
    # lang = "zh"
    session_id = f"save_test_{lang}_{timestamp}"
    
    # ===========================================
    # 根据语言设置对应的问题
    # ===========================================
    if lang == "zh":
        # 中文问题
        test_input = "2026年3月26日有哪些暴力破解记录"
    else:
        # 英文问题
        test_input = "What brute force attack records are there on March 26, 2026?"
    
    print(f"测试问题 ({lang.upper()})：{test_input}")
    print("-" * 50)
    
    try:
        result = call_and_save_stream_output(session_id, test_input, output_dir="./output", lang=lang)
        if result:
            print(f"\n保存成功！")
            print(f"原始数据：{result['jsonl_file']}")
            print(f"解析文件：{result['txt_file']}")
    except requests.exceptions.ConnectionError:
        print("无法连接到后端服务，请检查：1. 服务是否启动 2. 地址和端口是否正确")
    except Exception as e:
        print(f"调用异常：{str(e)}")
