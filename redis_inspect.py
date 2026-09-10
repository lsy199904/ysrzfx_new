# -*- coding: utf-8 -*-
"""
Redis 数据检查工具

用于查看 Redis 中存储的数据、内存使用情况、键空间等
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.redis_manager import RedisManager


async def inspect_redis():
    """检查 Redis 数据"""
    
    mgr = RedisManager(host="localhost", port=6379, db=0)
    await mgr.initialize()
    
    print("\n" + "=" * 60)
    print("Redis 数据存储检查")
    print("=" * 60)
    
    # 1. 基本信息
    print("\n【1. 连接信息】")
    print(f"  主机：localhost:6379")
    print(f"  数据库：DB 0")
    
    # 2. 内存信息
    print("\n【2. 内存使用】")
    info = await mgr.client.info("memory")
    used_memory = info.get("used_memory_human", "N/A")
    used_memory_peak = info.get("used_memory_peak_human", "N/A")
    print(f"  当前内存：{used_memory}")
    print(f"  峰值内存：{used_memory_peak}")
    
    # 3. 键空间信息
    print("\n【3. 键空间】")
    db_info = await mgr.client.info("keyspace")
    if db_info:
        for db_name, stats in db_info.items():
            print(f"  {db_name}: {stats}")
    else:
        print("  暂无数据")
    
    # 4. 查看所有键
    print("\n【4. 所有键列表】")
    cursor = 0
    all_keys = []
    while True:
        cursor, keys = await mgr.client.scan(cursor, count=100)
        all_keys.extend(keys)
        if cursor == 0:
            break
    
    if all_keys:
        print(f"  共 {len(all_keys)} 个键:\n")
        for key in sorted(all_keys):
            key_type = await mgr.client.type(key)
            ttl = await mgr.client.ttl(key)
            ttl_str = f"{ttl}s" if ttl > 0 else "永久"
            
            # 获取大小信息
            if key_type == "string":
                val = await mgr.client.get(key)
                size = len(val) if val else 0
                print(f"  [{key_type}] {key} (TTL: {ttl_str}, 大小：{size} 字节)")
            elif key_type == "list":
                length = await mgr.client.llen(key)
                print(f"  [{key_type}] {key} (TTL: {ttl_str}, 长度：{length})")
            elif key_type == "set":
                length = await mgr.client.scard(key)
                print(f"  [{key_type}] {key} (TTL: {ttl_str}, 元素数：{length})")
            elif key_type == "zset":
                length = await mgr.client.zcard(key)
                print(f"  [{key_type}] {key} (TTL: {ttl_str}, 元素数：{length})")
            elif key_type == "hash":
                length = await mgr.client.hlen(key)
                print(f"  [{key_type}] {key} (TTL: {ttl_str}, 字段数：{length})")
    else:
        print("  暂无数据")
    
    # 5. 按前缀分组统计
    print("\n【5. 按类型分组统计】")
    prefixes = {
        "session:": "会话数据",
        "cache:tool:": "工具缓存",
        "cache:query:": "查询缓存",
        "lock:": "分布式锁",
        "ratelimit:": "限流计数",
        "queue:": "消息队列",
        "user:": "用户会话",
    }
    
    for prefix, desc in prefixes.items():
        count = 0
        cursor = 0
        while True:
            cursor, keys = await mgr.client.scan(cursor, match=f"{prefix}*", count=100)
            count += len(keys)
            if cursor == 0:
                break
        if count > 0:
            print(f"  {desc} ({prefix}*): {count} 个")
    
    # 6. 查看会话数据示例
    print("\n【6. 会话数据示例】")
    cursor = 0
    session_keys = []
    while True:
        cursor, keys = await mgr.client.scan(cursor, match="session:*:history", count=10)
        session_keys.extend(keys)
        if cursor == 0 or len(session_keys) >= 3:
            break
    
    if session_keys:
        for key in session_keys[:3]:
            data = await mgr.client.get(key)
            ttl = await mgr.client.ttl(key)
            if data:
                import json
                history = json.loads(data)
                session_id = key.split(":")[1]
                print(f"\n  会话 ID: {session_id}")
                print(f"  消息数：{len(history)}")
                print(f"  剩余 TTL: {ttl}s")
                if history:
                    print(f"  第一条消息：{history[0].get('data', {}).get('content', '')[:50]}...")
    else:
        print("  暂无会话数据")
    
    print("\n" + "=" * 60)
    
    await mgr.close()


if __name__ == "__main__":
    asyncio.run(inspect_redis())