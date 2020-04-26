#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : _base_crawler.py
# -----------------------------------------------


class BaseCrawler:

    def __init__(self):
        self.timeout = 60


    def headers(self):
        return {
            'Accept' : '*/*',
            'Accept-Encoding' : 'gzip, deflate, br',
            'Accept-Language' : 'zh-CN,zh;q=0.9',
            'Connection' : 'keep-alive',
            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'
        }

