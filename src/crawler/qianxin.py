#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : qianxin.py
# -----------------------------------------------
# 奇安信：https://ti.qianxin.com/advisory/
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler

import requests
import json
import re


class QiAnXin(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.soure = '奇安信'
        self.url = 'https://ti.qianxin.com/advisory/'


    def get_cves(self):
        response = requests.get(
            self.url,
            headers = self.headers(),
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            html = response.content
            json_str = self.to_json(html)
            json_obj = json.loads(json_str)
            for obj in json_obj.get('msg'):
                print(obj)

            # if vul_list:
            #     vuls =  re.findall(r"<li><span>(.*?)</span> <a href='/vulndb/(\d+)'>(.*?)</a></li>", vul_list[0])
            #     for vul in vuls:
            #         cve = self.to_cve(vul)
            #         if cve.is_vaild():
            #             cves.append(cve)
            #             print(cve)
        else:
            print('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.soure, response.status_code))
        return cves


    def to_json(self, html):
        json_str = '{ "msg": [] }'
        rst = re.findall(r'(\{success:e,msg:.*?\],pageTotal)', html, re.DOTALL)
        if rst:
            json_str = rst[0]
            json_str = re.sub(r"content:'.*?',", "", json_str)
            json_str = re.sub(r'success:[\w\$]+,', '', json_str)
            json_str = re.sub(r'_id:[\w\$]+,', '', json_str)
            json_str = re.sub(r'title:[\w\$]+,', '', json_str)
            json_str = re.sub(r'category:[\w\$]+,', '', json_str)
            json_str = re.sub(r'isPdfArticle:[\w\$]+,', '', json_str)
            json_str = re.sub(r'isAdvisorArticle:[\w\$]+,', '', json_str)
            json_str = re.sub(r'author:[\w\$]+,', '', json_str)
            json_str = re.sub(r'headImg:[\w\$]+,', '', json_str)
            json_str = re.sub(r'descImg:[\w\$]+,', '', json_str)
            json_str = re.sub(r'pdfFile:[\w\$]+,', '', json_str)
            json_str = re.sub(r'iocFile:[\w\$]+,', '', json_str)
            json_str = re.sub(r'campaign:[\w\$]+,', '', json_str)
            json_str = re.sub(r'degree:[\w\$]+,', '', json_str)
            json_str = re.sub(r'area:\[.*?\],', '', json_str)
            json_str = re.sub(r'industries:\[.*?\],', '', json_str)
            json_str = re.sub(r'aggressor_type:\[.*?\],', '', json_str)
            json_str = json_str.replace('msg:', '"msg":')
            json_str = json_str.replace('readableId:', '"readableId":')
            json_str = json_str.replace('abstract:', '"abstract":')
            json_str = json_str.replace('publish_time:', '"publish_time":')
            json_str = json_str.replace('permlink:', '"permlink":')

            # json_str = re.sub(r"tags:(\[.*?\]),", '"tags":\'\1\',', json_str)
            json_str = json_str.replace(',pageTotal', '}')

        print(json_str)
        return json_str


    def to_cve(self, vul):
        cve = CVEInfo()
        cve.src = self.soure
        cve.url = self.url + vul[1]
        cve.time = vul[0] + ' --:--:--'
        cve.title = re.sub(r'\(CVE-\d+-\d+\)', '', vul[2])

        rst = re.findall(r'(CVE-\d+-\d+)', vul[2])
        cve.id = rst[0] if rst else ''
        return cve


