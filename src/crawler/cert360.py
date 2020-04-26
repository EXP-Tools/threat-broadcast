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


class Cert360(BaseCrawler):

    def __init__(self):
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

            for o in json_obj.get('data'):
                cve = CVEInfo()
                cve.url = self.url_cve + o.get('id')
                cve.time = o.get('add_time')
                cve.title = o.get('title')
                cve.id = cve.title
                cve.info = o.get('description')
                cve.src = '奇虎 360'

                cves.append(cve)
                print(cve)
        else :
            print()

        return cves

