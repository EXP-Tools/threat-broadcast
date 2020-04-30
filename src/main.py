#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

import sys
from src.cfg import env
from src.utils import log
from src.utils._sqlite import SqliteSDBC
import src.utils.page as page

from src.crawler.cert360 import Cert360
from src.crawler.nsfocus import Nsfocus
from src.crawler.qianxin import QiAnXin
from src.crawler.redqueen import RedQueen
from src.crawler.anquanke import AnQuanKe
from src.crawler.vas import Vas


def help_info():
    return '''
    -h                帮助信息
    -top <number>     播报时每个来源最多取最新的前 N 个 CVE （默认 10）
'''


def init():
    reload(sys)
    sys.setdefaultencoding(env.CHARSET)

    log.init()

    sdbc = SqliteSDBC(env.DB_PATH)
    sdbc.init(env.SQL_PATH)



def main(help, top):
    if help:
        log.info(help_info())

    else:
        srcs = [ Cert360(), Nsfocus(), QiAnXin(), RedQueen(), AnQuanKe(), Vas() ]
        for src in srcs:
            msgs = src.cve_msgs()
            to_log(msgs)
            to_page(msgs, top)
            to_notice(msgs)


def to_log(msgs):
    map(lambda msg : log.info(msg), msgs)


def to_page(msgs, top):
    if msgs:
        page.to_page(top)


def to_notice(msgs):
    pass



def get_sys_args(sys_args) :
    help = False
    top = 10

    idx = 1
    size = len(sys_args)
    while idx < size :
        try :
            if sys_args[idx] == '-h' :
                help = True

            elif sys_args[idx] == '-top' :
                idx += 1
                top = int(sys_args[idx])

        except :
            pass
        idx += 1
    return help, top


if __name__ == '__main__':
    init()
    main(*get_sys_args(sys.argv))



