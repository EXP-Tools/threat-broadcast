#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

import sys
from src.utils import log
from src.crawler.cert360 import Cert360


def init():
    reload(sys)
    sys.setdefaultencoding('utf-8')
    log.init()


def main(a, b, c):
    cert360 = Cert360()
    cert360.get_cves()


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

