#!/usr/bin/env python
# -*- coding: utf-8 -*-
# NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities

import time
from datetime import datetime, timedelta, timezone
import requests
from color_log.clog import log
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils.severity import from_nvd


class NVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '美国国家漏洞数据库（NVD）'
        self.name_en = 'NVD'
        self.home_page = 'https://nvd.nist.gov/'
        self.url_list = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.url_cve = 'https://nvd.nist.gov/vuln/detail/'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def HOME_PAGE(self):
        return self.home_page

    def get_cves(self, limit=10):
        if limit <= 0:
            return []
        limit = min(limit, 2000)
        now = datetime.now(timezone.utc)
        params = {
            'pubStartDate': (now - timedelta(days=7)).isoformat(timespec='milliseconds'),
            'pubEndDate': now.isoformat(timespec='milliseconds'),
            'noRejected': '',
            'resultsPerPage': limit,
        }
        data = self.query(params)
        total = data['totalResults']
        if total > limit:
            # NVD returns oldest first; fetch the tail, respecting its keyless rate limit.
            time.sleep(6)
            params['startIndex'] = total - limit
            data = self.query(params)
        records = [entry['cve'] for entry in data['vulnerabilities']]
        records.sort(key=lambda record: record['published'], reverse=True)
        return [self.to_cve(record) for record in records
                if record.get('vulnStatus') != 'Rejected'][:limit]

    def query(self, params):
        for attempt in range(3):
            try:
                response = requests.get(self.url_list, headers=self.headers(),
                                        params=params, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as exc:
                if attempt == 2:
                    raise
                log.warn('[NVD] 网络请求失败，6 秒后重试：%s' % exc)
                time.sleep(6)
                continue
            if response.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                break
            log.warn('[NVD] HTTP %s，6 秒后重试' % response.status_code)
            time.sleep(6)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data.get('vulnerabilities'), list) or 'totalResults' not in data:
            raise ValueError('NVD API 返回格式异常')
        return data

    def to_cve(self, record):
        cve = CVEInfo()
        cve.src = self.NAME_CH()
        cve.id = record['id']
        cve.url = self.url_cve + cve.id
        cve.time = record['published'].replace('T', ' ').rstrip('Z')
        descriptions = record.get('descriptions', [])
        cve.info = next((item['value'] for item in descriptions if item['lang'] == 'en'), '')
        if not cve.info and descriptions:
            cve.info = descriptions[0]['value']
        cve.title = cve.info or cve.id
        cve.severity = from_nvd(record.get('metrics', {}))
        return cve
