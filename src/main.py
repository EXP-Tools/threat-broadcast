#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

# TODO: logging
import sys

from src.crawler.cert360 import Cert360

def init():
    reload(sys)
    sys.setdefaultencoding('utf-8')


def main():
    cert360 = Cert360()
    cert360.get_cves()


if __name__ == '__main__':
    init()
    main()

