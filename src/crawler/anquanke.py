#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 14:34
# @File   : anquanke.py
# -----------------------------------------------
# 安全客：https://www.anquanke.com/vul
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import time
import requests
import re


class AnQuanKe(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '安全客'
        self.name_en = 'AnQuanKe'
        self.home_page = 'https://www.anquanke.com/vul'
        self.url = 'https://www.anquanke.com/vul/'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self):
        response = requests.get(
            self.url,
            headers = self.headers(),
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            html = response.content.decode(self.charset)
            vul_table = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
            if vul_table:
                for vul in vul_table:
                    cve = self.to_cve(vul)
                    if cve.is_vaild():
                        cves.append(cve)
                        # log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.name_ch, response.status_code))
        return cves


    def to_cve(self, xml):
        cve = CVEInfo()
        cve.src = self.NAME_CH()

        rst = re.findall(r'href="/vul/(.*?)">(.*?)</a>', xml, re.DOTALL)
        if rst:
            cve.url = self.url + rst[0][0]
            cve.title = rst[0][1].strip()

        rst = re.findall(r'(CVE-\d+-\d+)', xml)
        if rst:
            cve.id = rst[0]

        rst = re.findall(r'</i>(\d\d\d\d-\d\d-\d\d)', xml)
        if rst:
            cve.time = rst[1] + time.strftime(" %H:%M:%S", time.localtime())

        return cve


