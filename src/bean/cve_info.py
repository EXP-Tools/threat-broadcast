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


    def md5(self):
        if not self.md5:
            data = '%s%s%s' % (self.id, self.title, self.url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5


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





