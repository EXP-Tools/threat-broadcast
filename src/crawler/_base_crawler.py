#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : _base_crawler.py
# -----------------------------------------------

from src.utils import log
from abc import ABCMeta, abstractmethod     # python不存在抽象类的概念， 需要引入abc模块实现


class BaseCrawler:

    __metaclass__ = ABCMeta # 定义为抽象类

    def __init__(self, timeout = 60, charset = 'utf-8'):
        self.name = 'unknow'
        self.timeout = timeout or 60
        self.charset = charset or 'utf-8'


    def headers(self):
        return {
            'Accept' : '*/*',
            'Accept-Encoding' : 'gzip, deflate, br',
            'Accept-Language' : 'zh-CN,zh;q=0.9',
            'Connection' : 'keep-alive',
            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
        }


    def cve_msgs(self):
        log.info('++++++++++++++++++++++++++++++++++++++++++++')
        log.info('正在获取 [%s] 威胁情报...' % self.name)
        old_cves = self.load_cache()
        try:
            new_cves = self.get_cves()
        except:
            new_cves = []
            log.error('获取 [%s] 威胁情报异常' % self.name)

        msgs = []
        for cve in new_cves:
            if cve.md5() in old_cves:
                msgs.append(cve.to_msg())
                self.to_cache(cve)
        log.info('得到 [%s] 最新威胁情报 [%s] 条' % (self.name, len(msgs)))
        log.info('--------------------------------------------')
        return msgs


    @abstractmethod
    def get_cves(self):
        # 获取最新的 CVE 信息
        # TODO in sub class
        return []       # CVEInfo


    def load_cache(self):
        return set(['1', '2'])


    def to_cache(self, cve):
        pass

