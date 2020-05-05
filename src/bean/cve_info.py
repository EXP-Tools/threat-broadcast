#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : cve_info.py
# -----------------------------------------------


import hashlib


class CVEInfo:

    def __init__(self):
        self.id = ''
        self.src = ''
        self.url = ''
        self.time = ''
        self.title = ''
        self.info = ''
        self.md5 = ''


    def is_vaild(self):
        return not not self.title


    def MD5(self):
        if not self.md5:
            data = '%s%s%s' % (self.id, self.title, self.url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5


    def to_html(self):
        return '<br/>'.join([
            "<br/>==============================================",
            "[<b>漏洞来源</b>] %s" % self.src,
            "[<b>漏洞编号</b>] <font color='blue'>%s</font>" % self.id,
            "[<b>披露时间</b>] %s" % self.time,
            "[<b>漏洞描述</b>] %s" % self.title,
            "[<b>相关链接</b>] <a href='%s'>%s</a>" % (self.url, self.url)
        ])


    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ TITLE ] %s" % self.title,
            "[ TIME  ] %s" % self.time,
            "[ CVE   ] %s" % self.id,
            "[ SRC   ] %s" % self.src,
            "[ URL   ] %s" % self.url
        ])


    def __str__(self):
        return self.__repr__()


    def __repr__(self):
        return '\n'.join([
            "\n==============================================",
            "[ TITLE ] %s" % self.title,
            "[ TIME  ] %s" % self.time,
            "[ CVE   ] %s" % self.id,
            "[ SRC   ] %s" % self.src,
            "[ URL   ] %s" % self.url,
            "[ INFO  ] %s" % self.info,
        ])





