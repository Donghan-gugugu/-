


import requests
import json
import urllib3
urllib3.disable_warnings()
import time
sj = int(time.time())
sj2 = sj - 3590
import pandas as pd
from collections import Counter
# print(sj2)

jilu_list = []

while True:
    url = "你的蜜罐API接口"

    payload = json.dumps({
      "start_time": sj2,
      "end_time": 0,
      "page_no": 1,
      "page_size": 200,
      "intranet":-1,
      "threat_label": [],
      "client_id": [],
      "service_name": [],
      "info_confirm": ""})

    headers = {
      'Content-Type': 'application/json'
    }

    response = requests.post( url, headers=headers, data=payload,verify=False)

    detail_list1 = response.json()
    detail_list2 =detail_list1['data']
    detail_list3 = detail_list2['detail_list']

    # 统计ip次数
    ip111 = []
    for i1 in detail_list3:
        ip111.append(i1["attack_ip"])
    data = pd.Series(ip111)
    most_common = dict(data.value_counts())    #  ip 次数

    data_list = []
    for i2 in detail_list3:
        data_list.append(i2)
    # 统计值
    count_dict = Counter(item['attack_ip'] for item in data_list)
    count_list = {}
    all_dict = []

    def manys(ip):
        for i in range(0, len(data_list)):
            if ip == data_list[i]["attack_ip"]:
                data = {ip: [data_list[i]["attack_ip"], data_list[i]["ip_location"], data_list[i]["client_name"],
                             data_list[i]["service_name"], data_list[i]["threat_name"], data_list[i]["create_time"]]}
                return data

    for ip, count in count_dict.items():
        count_list[ip] = count
        if count == 1:
            for i in range(0, len(data_list)):
                if ip == data_list[i]["attack_ip"]:
                    data = {ip: [data_list[i]["attack_ip"], data_list[i]["ip_location"], data_list[i]["client_name"],
                                 data_list[i]["service_name"], data_list[i]["threat_name"],
                                 data_list[i]["create_time"]]}
                    all_dict.append(data)
        else:
            data = manys(ip)
            all_dict.append(data)

    print(most_common)
    # print(all_dict)

    for k,v in most_common.items():
        kk = k
        vv = v
        if int(vv) > 100 :
            for i in all_dict:
                for kkk,vvv in i.items():

                    n = time.localtime(vvv[5])  # 将时间戳转换成时间元祖tuple
                    ksj = time.strftime("%Y-%m-%d %H:%M:%S", n)  # 格式化输出时间

                    if kkk == kk :
                        fa1 = "IP：{}".format(vvv[0])
                        fa2 = "国家：{}".format(vvv[1])
                        fa3 = "受攻击节点：{}".format(vvv[2])
                        fa4 = "捕获：{}".format(vvv[3])
                        fa5 = "最近一次攻击：{}".format(ksj)

                        ff = fa1+' '+' '+' '+fa2+' '+' '+' '+fa3+' '+' '+' '+fa4+' '+' '+' '+fa5

                        if ff in jilu_list:     # 如果符合的数据  和上一次的数据结果一样 或者发送过  则舍弃 不发送
                            time.sleep(600)  # 休息时间
                            pass
                        else:

                            jilu_list.append(ff)  # 符合条件的放入列表

                            url = "https://open.larksuite.com/open-apis/你的飞书接收消息机器人地址"

                            payload_message = {
                            "msg_type": "text",
                            "content": {
                            "text": ff
                            }
                            }
                            headers = {
                            'Content-Type': 'application/json'
                            }

                            response = requests.request("POST", url, headers=headers, data=json.dumps(payload_message),verify=False)


                            time.sleep(600)              # 休息时间
                            if len(jilu_list) >= 50:    # 列表累计数量 超过了 清空
                                jilu_list = []
                            else:
                                pass















































