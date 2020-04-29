#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/29 23:30
# @File   : t_cves.py
# -----------------------------------------------
# PDM: t_cves
# -----------------------------------------------

class TCves:
    table_name = "t_cves"
    s_md5 = "s_md5"
    s_src = "s_src"
    s_cves = "s_cves"
    s_title = "s_title"
    s_time = "s_time"
    s_info = "s_info"
    s_url = "s_url"


    def __init__(self):
        self.md5 = None
        self.src = None
        self.cves = None
        self.title = None
        self.time = None
        self.info = None
        self.url = None


    def params(self):
        return (
            self.md5,
            self.src,
            self.cves,
            self.title,
            self.time,
            self.info,
            self.url,
        )


    def __repr__(self):
        return "\n".join(
            (
                "%s: {" % self.table_name,
                "\t%s = %s" % (self.s_md5, self.md5),
                "\t%s = %s" % (self.s_src, self.src),
                "\t%s = %s" % (self.s_cves, self.cves),
                "\t%s = %s" % (self.s_title, self.title),
                "\t%s = %s" % (self.s_time, self.time),
                "\t%s = %s" % (self.s_info, self.info),
                "\t%s = %s" % (self.s_url, self.url),
                "}\n"
            )
        )


