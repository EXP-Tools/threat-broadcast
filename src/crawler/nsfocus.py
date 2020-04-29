#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : nsfocus.py
# -----------------------------------------------
# 绿盟：http://www.nsfocus.net/vulndb
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import re


class Nsfocus(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '绿盟'
        self.name_en = 'Nsfocus'
        self.url = 'http://www.nsfocus.net/vulndb/'


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en



    def get_cves(self):
        response = requests.get(
            self.url,
            headers = self.headers(),
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            html = response.content
            vul_list = re.findall(r'<div class="vulbar">(.*?)</div>', html, re.DOTALL)
            if vul_list:
                vuls =  re.findall(r"<li><span>(.*?)</span> <a href='/vulndb/(\d+)'>(.*?)</a></li>", vul_list[0])
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
        cve.url = self.url + vul[1]
        cve.time = vul[0] + ' 00:00:00'
        cve.title = re.sub(r'\(CVE-\d+-\d+\)', '', vul[2])

        rst = re.findall(r'(CVE-\d+-\d+)', vul[2])
        cve.id = rst[0] if rst else ''
        return cve



