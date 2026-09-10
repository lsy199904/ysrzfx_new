"""
告警规则查询工具
"""
import time
import base64

import pandas as pd
import requests
import json
from pydantic import BaseModel, Field
from datetime import datetime

# 配置常量
SSO_APP_ID = "sso20251001"
SSO_SECRET_KEY = "C0HJU0La2o6qtgJ4ZvLk"
# API_DOMAIN = "http://10.180.158.96:8888"
API_DOMAIN = "https://192.168.101.54:8888"

# API_DOMAIN = "https://43.139.108.247:8888"
# API_DOMAIN = "http://203.85.9.168:8888"

# SSO_APP_ID = "111"
# SSO_SECRET_KEY = "11"
# API_DOMAIN = "111"
# # API_DOMAIN = "http://218.97.38.113:50134"
# ACCOUNT_GID = "111"
# ACCOUNT_EMAIL = "1111"

# 发送POST请求的公共方法
def send_post_request(url, payload, headers=None):
    headers = headers or {"Content-Type": "application/json"}
    try:
        response = requests.post(
            url,
            json=payload,  # 自动序列化并设置Content-Type
            headers=headers,
            timeout=50,     # 添加超时设置
            verify=False#禁用 SSL 证书验证
        )
        print('***************')
        print(response.text)
        print('***************')
        response.raise_for_status()#检查 HTTP 状态码
        return response
    except requests.exceptions.RequestException as e:
        print(f"请求错误 [{url}]: {e}")
        return None

# 生成签名密钥
def generate_signature():
    """
    生成签名密钥
    """
    timestamp = int(time.time())
    encode_str = f"{SSO_APP_ID}{SSO_SECRET_KEY[:3]}{SSO_SECRET_KEY[-3:]}{timestamp}"
    return base64.b64encode(encode_str.encode()).decode()



def data_group(out):
    """
    定义数据聚合函数
    """
    data=out['data']['dataList']
    data=pd.DataFrame(data)
    if len(data)>0:
        data=data.groupby(['gid','fix_source_type','event_threat_type','event_mitre_att_ck_technique'
                              ,'event_source_ip','event_signature','event_destination_ip','event_mitre_att_ck_tactic',
                           'event_threat_name','event_hostname']).agg(
            threat_count=('event_date_time','count'),#聚合：计算告警数量，统计每个分组的记录数
            time_range=('event_date_time',lambda x: sorted(list(set(x.tolist())))),
        ).reset_index()
        data=data.to_dict("records")
    else:
        data=out
    return data


def query_alert_rule_result(
    gid: str = None,  # 给参数加默认值None
    start_time: str = None,  # 给参数加默认值None
    end_time: str = None     # 给参数加默认值None
):
    """
    定义查询告警规则结果的函数
    """
    if start_time:  # 先判断start_time不为空（避免None时报错）
        try:
            # 尝试解析「带时分秒」的格式（优先处理Agent传入的完整格式）
            start_datetime = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # 解析失败时，再尝试「仅日期」的格式
            start_datetime = datetime.strptime(start_time, '%Y-%m-%d')
        # 统一转为「YYYY-MM-DD 00:00:00」格式（不管原格式是哪种）
        start_time = start_datetime.strftime('%Y-%m-%d 00:00:00')
    else:
        # 若start_time为None（未传入），设为当天0点（可选，根据你的默认逻辑）
        start_time = datetime.now().strftime('%Y-%m-%d 00:00:00')

        # -------------------------- 修复：处理end_time格式 --------------------------
    if end_time:  # 同理处理end_time
        try:
            # 尝试解析「带时分秒」的格式
            end_datetime = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # 解析失败时，尝试「仅日期」的格式
            end_datetime = datetime.strptime(end_time, '%Y-%m-%d')
        # 统一转为「YYYY-MM-DD 23:59:59」（避免和start_time同一天时查询范围为空）
        end_time = end_datetime.strftime('%Y-%m-%d 23:59:59')
    else:
        # 若end_time为None（未传入），设为当前时间（可选）
        end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # table_name="alarm_rule_result"
    table_name="alarm_result"
    sign_key = generate_signature()
    page_no = 1#查询第 1 页
    page_size = 500#每页 500 条
    print(f"\n查询告警规则 [表: {table_name}, GID: {gid}, 开始时间：{start_time}, 结束时间：{end_time}, 当前页码：{page_no}, 每页大小：{page_size}]")
    url = f"{API_DOMAIN}/admin/sdk/alert-rule-result"
    headers = {}
    if gid:#如果有客户 ID
        payload = {
            "sdkReq": {"appId": SSO_APP_ID, "signKey": sign_key},
            "gid": gid,
            "tableName": table_name,
            "createTime": [start_time, end_time],
            "pageNo": page_no,
            "pageSize": page_size
        }
    else:#没有 gid 时的处理
        payload = {
            "sdkReq":{"appId": SSO_APP_ID,"signKey": sign_key},
            "gid": "",
            "tableName": table_name,
            "createTime": [start_time, end_time],
            "pageNo": page_no,
            "pageSize": page_size
        }
    #同时赋值和判断
    if response := send_post_request(url, payload, headers):
        # print("响应结果:", response.json())
        out=response.json()
        out=data_group(out)
    else:
        print("查询失败")
        out='告警查询失败'
    return out

def alert_rule_request(
    gid: str = None,  # 关键：添加默认值None
    start_time: str = None,  # 添加默认值None
    end_time: str = None     # 添加默认值None
):
    """
    定义告警规则请求函数
    """
    # print(f"入参:{token} - {gid} - {type(table_name)} - {type(days)}")
    return query_alert_rule_result(gid,start_time, end_time)


class AlertruleInput(BaseModel):
    """
    定义输入参数模型
    """
    gid: str = Field(default=None,description="客户的gid编号，客户的唯一标识。可选参数，若不指定则查询所有客户的规则结果")
    start_time: str = Field(default=None,description="要查询的规则结果的开始时间.可选参数，若不指定，则默认为当天0点")
    end_time: str = Field(default=None,description="要查询的规则结果的结束时间.可选参数，若不指定，则默认为当前时间")

if __name__ == '__main__':
    # query_alert_rule_result("44926",start_time='2025-01-01',end_time='2025-3-31')
    query_alert_rule_result(start_time='2025-01-03',end_time='2025-03-31')
