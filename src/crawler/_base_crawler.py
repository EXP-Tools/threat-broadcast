#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : _base_crawler.py
# -----------------------------------------------

import os
from datetime import datetime, timezone
from abc import ABCMeta, abstractmethod     # python不存在抽象类的概念， 需要引入abc模块实现
import src.config as config
from color_log.clog import log
from pypdm.dbc._sqlite import SqliteDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao



class BaseCrawler:

    __metaclass__ = ABCMeta # 定义为抽象类

    def __init__(self, timeout = None, charset = config.CHARSET):
        self.timeout = timeout or config.settings.crawler.get('timeout', 20)
        self.charset = charset or config.CHARSET
        self.last_error = None


    @abstractmethod
    def NAME_CH(self):
        return '未知'


    @abstractmethod
    def NAME_EN(self):
        return 'unknow'


    @abstractmethod
    def HOME_PAGE(self):
        return 'https://exp-blog.com'


    def CACHE_PATH(self):
        return '%s/cache/%s.dat' % (config.PRJ_DIR, self.NAME_EN())


    def headers(self):
        return {
            'Accept' : '*/*',
            'Accept-Encoding' : 'gzip, deflate',
            'Accept-Language' : 'zh-CN,zh;q=0.9',
            'Connection' : 'keep-alive',
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        }


    def fetch_cves(self):
        cves = self.get_cves()
        if not cves:
            raise ValueError('未获取到有效情报，请检查数据接口或解析规则')
        max_age = config.settings.crawler.get('max_age_days', 90)
        if cves and max_age:
            latest = max(datetime.fromisoformat(str(cve.time).replace('Z', '+00:00')).date()
                         for cve in cves)
            if (datetime.now(timezone.utc).date() - latest).days > max_age:
                raise ValueError('来源疑似停更：最新情报日期 %s，超过 %s 天' % (latest, max_age))
        return cves


    def cves(self):
        log.info('++++++++++++++++++++++++++++++++++++++++++++')
        log.info('正在获取 [%s] 威胁情报...' % self.NAME_CH())
        old_cves = self.load_cache()

        self.last_error = None
        try:
            new_cves = self.fetch_cves()
        except Exception as exc:
            self.last_error = '%s: %s' % (type(exc).__name__, exc)
            log.error('获取 [%s] 威胁情报失败：%s' % (self.NAME_CH(), self.last_error))
            return []

        dao = TCvesDao()
        sdbc = SqliteDBC(options=config.settings.database)
        conn = sdbc.conn()
        _cves = []
        try:
            for cve in new_cves:
                if cve.MD5() not in old_cves:
                    if self.to_db(conn, dao, cve):
                        self.to_cache(cve)
                        old_cves.add(cve.MD5())
                        _cves.append(cve)
                    else:
                        self.last_error = '数据库写入失败'
        finally:
            sdbc.close()

        log.info('得到 [%s] 最新威胁情报 [%s] 条' % (self.NAME_CH(), len(_cves)))
        log.info('--------------------------------------------')
        return _cves


    @abstractmethod
    def get_cves(self):
        # 获取最新的 CVE 信息（由子类爬虫实现）
        # TODO in sub class
        return []       # CVEInfo


    def load_cache(self):
        if not os.path.exists(self.CACHE_PATH()):
            with open(self.CACHE_PATH(), 'w+', newline='\n') as file:
                 pass   # 创建空文件

        lines = []
        with open(self.CACHE_PATH(), 'r+') as file:
            lines = file.readlines()
            lines = list(map(lambda line: line.strip(), lines))

        # 缓存超过 200 时，保留最后的 100 条缓存
        if len(lines) > 200:
            lines = lines[-100:]
            with open(self.CACHE_PATH(), 'w+', newline='\n') as file:
                file.write('\n'.join(lines) + '\n')
        return set(lines)


    def to_cache(self, cve):
        with open(self.CACHE_PATH(), 'a+', newline='\n') as file:
            file.write(cve.MD5() + '\n')


    def to_db(self, conn, dao, cve):
        tcve = TCves()
        tcve.md5 = cve.MD5()
        tcve.src = cve.src
        tcve.cves = cve.id
        tcve.title = cve.title
        tcve.info = cve.info
        tcve.time = cve.time
        tcve.url = cve.url
        return dao.insert(conn, tcve)
