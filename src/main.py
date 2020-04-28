#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

import sys
from src.utils import log

from src.crawler.cert360 import Cert360
from src.crawler.nsfocus import Nsfocus
from src.crawler.qianxin import QiAnXin
from src.crawler.redqueen import RedQueen


def init():
    reload(sys)
    sys.setdefaultencoding('utf-8')
    log.init()


def main(a, b, c):
    srcs = [ Cert360(), Nsfocus(), QiAnXin(), RedQueen() ]
    for src in srcs:
        src.cve_msgs()



def get_sys_args(sys_args) :
    a = ''
    b = ''
    c = ''

    idx = 1
    size = len(sys_args)
    while idx < size :
        try :
            if sys_args[idx] == '-h' :
                idx += 1
                a = int(sys_args[idx])

            elif sys_args[idx] == '-m' :
                idx += 1
                b = int(sys_args[idx])

            elif sys_args[idx] == '-s' :
                idx += 1
                c = int(sys_args[idx])
        except :
            pass
        idx += 1
    return a, b, c


if __name__ == '__main__':
    init()
    main(*get_sys_args(sys.argv))

