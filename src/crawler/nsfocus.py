#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 绿盟科技安全漏洞库: https://www.nsfocus.net/

import re
import requests
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils.severity import normalize


class Nsfocus(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '绿盟'
        self.name_en = 'Nsfocus'
        self.home_page = 'https://www.nsfocus.net/'
        self.url_list = 'https://www.nsfocus.net/official/api/v1/vulns/'
        self.url_cve = 'https://www.nsfocus.net/vulndb/'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=10):
        if limit <= 0:
            return []
        response = requests.get(self.url_list, headers=self.headers(),
                                params={'page': 1, 'page_size': limit}, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data.get('results'), list):
            raise ValueError('绿盟 API 返回格式异常')
        cves = [self.to_cve(item) for item in data['results'][:limit]]
        return [cve for cve in cves if cve.is_vaild()]

    def to_cve(self, item):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + str(item['bug_id'])
        # Keep the source date rather than inventing a timestamp on each run.
        cve.time = item['update_time']
        title = item['bug_name']
        cve.title = re.sub(r'\(CVE-\d+-\d+\)|（CVE-\d+-\d+）', '', title).strip()
        cve.id = ', '.join(re.findall(r'CVE-\d+-\d+', title))
        cve.severity = normalize(item.get('severity'))
        return cve
