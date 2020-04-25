#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

from src.bean.cve_info import CVEInfo

import sys
import requests
import json



def init():
    reload(sys)
    sys.setdefaultencoding('utf-8')


def get_headers(nv_cookies=''):
    '''
    获取HTTP请求头(主要设置HTTP代理, 避免被反爬)
    :return: HTTP请求头
    '''
    headers = {
        'Accept' : '*/*',
        'Accept-Encoding' : 'gzip, deflate, br',
        'Accept-Language' : 'zh-CN,zh;q=0.9',
        'Connection' : 'keep-alive',
        'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'
    }
    return headers


def main():
    url = 'https://cert.360.cn/warning/searchbypage?length=10&start=0'
    timeout = 60
    headers = get_headers()
    params = {
        'length': 6,
        'start' : 0
    }

    response = requests.get(url, headers=headers, params=params, timeout=timeout)
    if response.status_code == 200:
        json_obj = json.loads(response.text)

        for o in json_obj.get('data'):
            cve = CVEInfo()
            cve.url = 'https://cert.360.cn/warning/detail?id='+ o.get('id')
            cve.time = o.get('add_time')
            cve.title = o.get('title')
            cve.id = cve.title
            cve.info = o.get('description')
            print(cve)



if __name__ == '__main__':
    init()
    main()

