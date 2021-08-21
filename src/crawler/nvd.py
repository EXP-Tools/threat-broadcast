#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : redqueen.py
# -----------------------------------------------
# NVD：https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import re
from lxml import etree


class NVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '美国国家漏洞数据库（NVD）'
        self.name_en = 'NVD'
        self.home_page = 'https://nvd.nist.gov/'
        self.url_list = 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml'
        self.url_cve = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId='


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 10):
        response = requests.get(
            self.url_list,
            headers = self.headers(),
            timeout = self.timeout
        )

        cves = []
        if response.status_code == 200:
            data = ''.join(response.text.split('\n')[1:])
            data = re.sub(r'dc:date', 'dc_date', data)
            rdf = etree.HTML(data)
            items = rdf.xpath("//item")

            cnt = 0
            for item in reversed(items) :
                cve = self.to_cve(item)
                if cve.is_vaild():
                    if cnt < limit :
                        cves.append(cve)
                        # log.debug(cve)
                        cnt += 1
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, item):
        cve = CVEInfo()
        cve.src = self.NAME_CH()

        _id = item.xpath("./title")[0].text
        cve.id = re.sub(r' \(.*?\)', '', _id)
        cve.url = self.url_cve + cve.id

        _time = item.xpath("./dc_date")[0].text
        cve.time = _time.replace('T', ' ').replace('Z', ' ')

        cve.info = item.xpath("./description")[0].text
        cve.title = cve.info
        return cve
