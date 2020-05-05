#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 14:38
# @File   : vas.py
# -----------------------------------------------
# 斗象：https://vas.riskivy.com/vuln
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import json
import re
import time


class Vas(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '斗象'
        self.name_en = 'vas'
        self.home_page = 'https://vas.riskivy.com/vuln'
        self.url_list = 'https://console.riskivy.com/vas'
        self.url_details = 'https://console.riskivy.com/vas/'
        self.url_cve = 'https://vas.riskivy.com/vuln-detail?id='


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 5):
        params = {
            'title': '',
            'cve' : '',
            'cnvd': '',
            'cnnvd': '',
            'order': 'update',
            'has_poc': '',
            'has_repair': '',
            'bug_level': '',
            'page': 1,
            'per-page': limit,
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
            for obj in json_obj.get('data').get('items'):
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

        id = str(json_obj.get('id')) or ''
        cve.url = self.url_cve + id
        cve.title =  json_obj.get('bug_title') or ''

        seconds = json_obj.get('updated_at') or 0
        localtime = time.localtime(seconds)
        cve.time = time.strftime('%Y-%m-%d %H:%M:%S', localtime)

        self.get_cve_info(cve, id)
        return cve


    def get_cve_info(self, cve, id):
        url = self.url_details + id
        response = requests.get(
            url,
            headers = self.headers(),
            timeout = self.timeout
        )

        if response.status_code == 200:
            json_obj = json.loads(response.text)
            cve.id = json_obj.get('data').get('bug_cve').replace(',', ', ')
            cve.info = json_obj.get('data').get('detail').get('bug_description')
            cve.info = re.sub(r'<.*?>', '', cve.info)

        time.sleep(0.1)

