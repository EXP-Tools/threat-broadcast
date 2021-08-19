#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/12/01 23:21
# @File   : cnnvd.py
# -----------------------------------------------
# cnnvd: http://www.cnnvd.org.cn/
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
from requests.utils import add_dict_to_cookiejar
import execjs
import hashlib
import json
import re
import time


class CNVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'CNVD'
        self.name_en = 'CNVD'
        self.home_page = ''
        self.url_list = ''
        self.url_cve = ''

        self.session = requests.session()
        self._set_cookie(self.home_page)


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 6):
        params = {
            'length': limit,
            'start' : 0
        }

        response = self.session.get(
            self.url_list,
            params = params,
            timeout = self.timeout
        )
        response.encoding = 'utf-8'

        cves = []
        if response.status_code == 200:
            ids = re.findall(r'\thref="/flaw/show/([^"]+)"', response.text)
            print(ids)
            for id in ids :
                cve = self.to_cve(id)
                if cve.is_vaild():
                    cves.append(cve)
                    log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, id):
        cve = CVEInfo()
        cve.id = id
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + id
        self.get_cve_info(cve, cve.url)
        return cve


    def get_cve_info(self, cve, url) :
        try :
            response = self.session.get(
                url,
                timeout = self.timeout
            )
            response.encoding = 'utf-8'

            if response.status_code == 200:
                cve.title = re.findall(r'>(.*?)</h1>', response.text)[0].strip()
                kvs = re.findall(r'<td class="alignRight">(.*?)</td>.*?<td>(.*?)</td>', response.text, re.DOTALL)
                for kv in kvs :
                    key = kv[0].replace('\t', '').strip()
                    val = kv[1].replace('\t', '').strip()
                    
                    if key == 'CVE ID' :
                        id = re.findall(r'>(.*?)</a>', val)[0].strip()
                        cve.id = "%s (%s)" % (cve.id, id)

                    elif key == '公开日期' :
                        cve.time = val + time.strftime(" %H:%M:%S", time.localtime())

                    elif key == '漏洞描述' :
                        cve.info = val.replace('\r', '').replace('\n', '').replace('<br/>', '')
        except :
            pass  # 漏洞信息页面不存在

        time.sleep(1)

