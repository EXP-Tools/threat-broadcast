#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : redqueen.py
# -----------------------------------------------
# 红后：https://redqueen.tj-un.com/IntelHome.html
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import json
import re


class RedQueen(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '红后'
        self.name_en = 'RedQueen'
        self.home_page = 'https://redqueen.tj-un.com/IntelHome.html'
        self.url_list = 'https://redqueen.tj-un.com/Json/intelHomeVulnIntelList.json'
        self.url_cve = 'https://redqueen.tj-un.com/IntelDetails.html?id='


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def to_headers(self):
        headers = self.headers()
        headers['Host'] = 'redqueen.tj-un.com'
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        return headers


    def get_cves(self, limit = 10):
        data = 'query={ "page": 1, "page_count": %d }' % limit

        response = requests.post(
            self.url_list,
            headers = self.to_headers(),
            data = data,
            timeout = self.timeout
        )
        
        cves = []
        if response.status_code == 200:
            json_obj = json.loads(response.text)
            for obj in json_obj.get('intgs'):
                cve = self.to_cve(obj)
                if cve.is_vaild():
                    cves.append(cve)
                    # log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + json_obj.get('id')
        # cve.time = json_obj.get('pub_time')
        cve.time = json_obj.get('upd_time')

        title = json_obj.get('title')
        rst = re.findall(r'CVE-\d+-\d+|CNVD-\d+-\d+', title)
        cve.id = rst[0] if rst else ''
        cve.title = re.sub(r'CVE-\d+-\d+|CNVD-\d+-\d+', '', title).strip()
        return cve
