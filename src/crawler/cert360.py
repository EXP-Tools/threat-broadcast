#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : cert360.py
# -----------------------------------------------
# 360：https://cert.360.cn/warning
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler

import requests
import json
import re


class Cert360(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.soure = '奇虎 360'
        self.url_list = 'https://cert.360.cn/warning/searchbypage'
        self.url_cve = 'https://cert.360.cn/warning/detail?id='


    def get_cves(self, limit = 6):
        params = {
            'length': limit,
            'start' : 0
        }

        response = requests.get(
            self.url_list,
            headers = self.headers(),
            params = params,
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            json_obj = json.loads(response.text)
            for obj in json_obj.get('data'):
                cve = self.to_cve(obj)
                cves.append(cve)
        else :
            print('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.soure, response.status_code))

        return cves


    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.soure
        cve.url = self.url_cve + json_obj.get('id')
        cve.time = json_obj.get('add_time')
        cve.title = json_obj.get('title')
        cve.info = json_obj.get('description')

        rst = re.findall(r'(CVE-\d+-\d+)', cve.title)
        cve.id = rst[0] if rst else ''

        print(cve)


