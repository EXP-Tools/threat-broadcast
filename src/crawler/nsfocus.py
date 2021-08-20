#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : nsfocus.py
# -----------------------------------------------
# 绿盟：http://www.nsfocus.net/index.php
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import time
import requests
import re


class Nsfocus(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '绿盟'
        self.name_en = 'Nsfocus'
        self.home_page = 'http://www.nsfocus.net/index.php'
        self.url_list = 'http://www.nsfocus.net/index.php'
        self.url_cve = 'http://www.nsfocus.net/vulndb/'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self):
        params = {
            'act': 'sec_bug'
        }

        response = requests.get(
            self.url_list,
            headers = self.headers(),
            params = params,
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            html = response.content.decode(self.charset)
            vul_list = re.findall(r'<div class="vulbar">(.*?)</div>', html, re.DOTALL)
            if vul_list:
                vuls =  re.findall(r"<li><span>(.*?)</span> <a href='/vulndb/(\d+)'>(.*?)</a>", vul_list[0])
                for vul in vuls:
                    cve = self.to_cve(vul)
                    if cve.is_vaild():
                        cves.append(cve)
                        # log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, vul):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + vul[1]
        cve.time = vul[0] + time.strftime(" %H:%M:%S", time.localtime())
        cve.title = re.sub(r'\(CVE-\d+-\d+\)|（CVE-\d+-\d+）', '', vul[2])

        rst = re.findall(r'(CVE-\d+-\d+)', vul[2])
        cve.id = rst[0] if rst else ''
        return cve



