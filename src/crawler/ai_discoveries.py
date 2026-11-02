#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Public, explicitly attributed AI-discovered vulnerability disclosures."""

import json
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests
import yaml
from lxml import html
from color_log.clog import log

import src.config as config
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils.severity import normalize


class AISLE(BaseCrawler):
    """AISLE's own CVE catalogue, with dates from each disclosure's JSON-LD."""

    def NAME_CH(self):
        return 'AISLE（AI 发现）'

    def NAME_EN(self):
        return 'AISLE'

    def HOME_PAGE(self):
        return 'https://aisle.com/cve-discoveries'

    def get_cves(self):
        response = requests.get(self.HOME_PAGE(), headers=self.headers(), timeout=self.timeout)
        response.raise_for_status()
        candidates = self.parse_catalog(response.content)
        known = self.load_archived()

        def fetch(candidate):
            identifier, title, url, severity = candidate
            if url in known:
                known[url].severity = severity or known[url].severity
                return known[url]
            try:
                response = requests.get(url, headers=self.headers(), timeout=self.timeout)
                response.raise_for_status()
                cve = self.parse_detail(response.content, identifier, title, url)
                cve.severity = severity
                return cve
            except Exception as exc:
                log.warn('[AISLE] %s 抓取失败：%s: %s' % (identifier, type(exc).__name__, exc))
                return None

        # Existing archive records avoid re-downloading hundreds of detail pages.
        # Limit concurrency so the first collection does not overwhelm the source.
        with ThreadPoolExecutor(max_workers=3) as pool:
            cves = [cve for cve in pool.map(fetch, candidates) if cve is not None]
        cutoff = (datetime.now(timezone.utc) - timedelta(
            days=config.settings.crawler.get('max_age_days', 90) or 90)).date()
        cves = [cve for cve in cves if datetime.fromisoformat(cve.time).date() >= cutoff]
        return sorted(cves, key=lambda cve: cve.time, reverse=True)

    def parse_catalog(self, content):
        doc = html.fromstring(content)
        sections = doc.xpath('//section[@data-wall-section]')
        if not sections:
            raise ValueError('AISLE CVE 目录结构已变化')
        max_age = config.settings.crawler.get('max_age_days', 90)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age or 90)).date()
        candidates = {}
        for section in sections:
            label = section.xpath('string(./header/h2)').strip()
            month = datetime.strptime(label, '%B %Y').date()
            if (month.year, month.month) < (cutoff.year, cutoff.month):
                continue
            for item in section.xpath('.//li[@data-cve]'):
                links = item.xpath('./a/@href')
                if not links or not re.fullmatch(r'/cve-discoveries/cve-\d{4}-\d{4,}', links[0]):
                    continue
                identifier = links[0].rsplit('/', 1)[-1].upper()
                title = item.xpath('string(./a/p)').strip()
                product = item.get('data-product', '')
                if not title:
                    raise ValueError('AISLE %s 缺少漏洞标题' % identifier)
                url = urljoin(self.HOME_PAGE(), links[0])
                candidates[url] = (identifier, '%s: %s' % (product, title), url,
                                   normalize(item.get('data-severity')))
        return list(candidates.values())

    def parse_detail(self, content, identifier, title, url):
        doc = html.fromstring(content)
        for text in doc.xpath('//script[@type="application/ld+json"]/text()'):
            data = json.loads(text)
            if not isinstance(data, dict) or data.get('@type') != 'TechArticle':
                continue
            if identifier not in data.get('headline', '') or 'AISLE' not in data['headline']:
                raise ValueError('AISLE 披露的 CVE 或发现者不匹配')
            cve = CVEInfo()
            cve.src, cve.id, cve.title, cve.url = self.NAME_CH(), identifier, title, url
            published = datetime.fromisoformat(data['datePublished'].replace('Z', '+00:00'))
            cve.time = published.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            cve.info = 'AI 发现依据：AISLE 官方 CVE 目录及披露。\n' + data.get('description', '')
            return cve
        raise ValueError('AISLE 披露缺少 TechArticle 日期元数据')

    def load_archived(self):
        dbpath = config.settings.database.get('dbpath')
        if not dbpath or not Path(dbpath).is_file():
            return {}
        known = {}
        try:
            uri = Path(dbpath).resolve().as_uri() + '?mode=ro'
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                rows = conn.execute(
                    'select s_cves,s_title,s_time,s_info,s_url,s_severity from t_cves where s_src = ?',
                    (self.NAME_CH(),)).fetchall()
            for identifier, title, published, info, url, severity in rows:
                cve = CVEInfo()
                cve.src, cve.id, cve.title = self.NAME_CH(), identifier, title
                cve.time, cve.info, cve.url = published, info, url
                cve.severity = normalize(severity)
                known[url] = cve
        except sqlite3.OperationalError as exc:
            log.warn('[AISLE] 无法读取已有归档，将直接读取披露：%s' % exc)
        return known


class MozillaAI(BaseCrawler):
    # Employer names alone do not establish that a vulnerability was AI-discovered.
    AI_REPORTER = re.compile(r'\b(?:Claude|Mythos|Codex Security|Big\s?Sleep|CodeMender)\b', re.I)
    REPO = 'https://raw.githubusercontent.com/mozilla/foundation-security-advisories/main/announce'

    def NAME_CH(self):
        return 'Mozilla（AI 发现）'

    def NAME_EN(self):
        return 'Mozilla AI'

    def HOME_PAGE(self):
        return 'https://www.mozilla.org/en-US/security/advisories/'

    def get_cves(self):
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(days=config.settings.crawler.get('max_age_days', 90) or 90)).date()
        candidates = []
        for year in range(cutoff.year, now.year + 1):
            response = requests.get(
                'https://api.github.com/repos/mozilla/foundation-security-advisories/contents/announce/%s' % year,
                headers=self.headers(), timeout=self.timeout)
            response.raise_for_status()
            files = response.json()
            if not isinstance(files, list):
                raise ValueError('Mozilla 通告目录返回格式异常')
            for item in files:
                match = re.fullmatch(r'mfsa\d{4}-(\d+)\.yml', item.get('name', ''))
                if match:
                    candidates.append((year, int(match[1]), item['name']))
        cves = {}
        for year, number, filename in sorted(candidates, reverse=True)[:6]:
            response = requests.get('%s/%s/%s' % (self.REPO, year, filename),
                                    headers=self.headers(), timeout=self.timeout)
            response.raise_for_status()
            data = yaml.safe_load(response.content)
            for cve in self.parse_advisory(data, filename[:-4]):
                if datetime.fromisoformat(cve.time).date() >= cutoff:
                    cves.setdefault(cve.id, cve)
        return sorted(cves.values(), key=lambda cve: (cve.time, cve.id), reverse=True)

    def parse_advisory(self, data, advisory):
        if not isinstance(data, dict) or not isinstance(data.get('advisories'), dict):
            raise ValueError('Mozilla 通告 YAML 返回格式异常')
        published = datetime.strptime(str(data['announced']), '%B %d, %Y').strftime('%Y-%m-%d')
        cves = []
        for identifier, item in data['advisories'].items():
            reporter = item.get('reporter', '')
            if isinstance(reporter, list):
                reporter = ', '.join(reporter)
            if not self.AI_REPORTER.search(reporter or ''):
                continue
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}', identifier):
                continue
            cve = CVEInfo()
            cve.src, cve.id, cve.title, cve.time = self.NAME_CH(), identifier, item['title'], published
            cve.severity = normalize(item.get('impact'))
            cve.url = '%s%s/#%s' % (self.HOME_PAGE(), advisory, identifier)
            cve.info = '官方通告发现者：%s\n修复版本：%s\n%s' % (
                reporter, ', '.join(data.get('fixed_in', [])), item.get('description', '') or '')
            cves.append(cve)
        return cves
