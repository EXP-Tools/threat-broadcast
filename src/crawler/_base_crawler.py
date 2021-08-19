#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : _base_crawler.py
# -----------------------------------------------

import os
from abc import ABCMeta, abstractmethod     # python不存在抽象类的概念， 需要引入abc模块实现
from src.cfg import env
from src.utils import log
from src.utils._sqlite import SqliteSDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao



class BaseCrawler:

    __metaclass__ = ABCMeta # 定义为抽象类

    def __init__(self, timeout = 60, charset = env.CHARSET):
        self.timeout = timeout or 60
        self.charset = charset or env.CHARSET


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
        return '%s/cache/%s.dat' % (env.PRJ_DIR, self.NAME_EN())


    def headers(self):
        return {
            'Accept' : '*/*',
            'Accept-Encoding' : 'gzip, deflate',
            'Accept-Language' : 'zh-CN,zh;q=0.9',
            'Connection' : 'keep-alive',
            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
        }


    def cves(self):
        log.info('++++++++++++++++++++++++++++++++++++++++++++')
        log.info('正在获取 [%s] 威胁情报...' % self.NAME_CH())
        old_cves = self.load_cache()

        try:
            new_cves = self.get_cves()
        except:
            new_cves = []
            log.error('获取 [%s] 威胁情报异常' % self.NAME_CH())

        dao = TCvesDao()
        sdbc = SqliteSDBC(env.DB_PATH)
        conn = sdbc.conn()
        _cves = []
        for cve in new_cves:
            if cve.MD5() not in old_cves:
                _cves.append(cve)
                self.to_cache(cve)
                self.to_db(conn, dao, cve)
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
            with open(self.CACHE_PATH(), 'w+') as file:
                 pass   # 创建空文件

        lines = []
        with open(self.CACHE_PATH(), 'r+') as file:
            lines = file.readlines()
            lines = list(map(lambda line: line.strip(), lines))

        # 缓存超过 200 时，保留最后的 100 条缓存
        if len(lines) > 200:
            lines = lines[100:]
            with open(self.CACHE_PATH(), 'w+') as file:
                file.write('\n'.join(lines) + '\n')
        return set(lines)


    def to_cache(self, cve):
        with open(self.CACHE_PATH(), 'a+') as file:
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
        dao.insert(conn, tcve)
