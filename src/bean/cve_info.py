#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : cve_info.py
# -----------------------------------------------


class CVEInfo:

    def __init__(self):
        self.id = ''
        self.url = ''
        self.time = ''
        self.title = ''
        self.info = ''

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return '\n'.join([
            "==============================================",
            "[CVE]   %s" % self.id,
            "[URL]   %s" % self.url,
            "[TIME]  %s" % self.time,
            "[TITLE] %s" % self.title,
            "[INFO]  %s" % self.info,
        ])





