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

from src.crawler.cert360 import Cert360
from src.crawler.nsfocus import Nsfocus
from src.crawler.qianxin import QiAnXin
from src.crawler.redqueen import RedQueen
from src.crawler.anquanke import AnQuanKe
from src.crawler.vas import Vas

import src.notice.page as page
import src.notice.mail as mail
import src.notice.qq as qq



def help_info():
    return '''
    -h                帮助信息
    -top <number>     播报时每个来源最多取最新的前 N 个 CVE（默认 10）
    -mu  <mail-user>  用于发送播报信息的邮箱账号（默认 threat-broadcast@foxmail.com）
    -mp  <mail-pass>  用于发送播报信息的邮箱密码
    -qu  <qq-user>    用于向 QQ 群发送播报信息的 QQ 账号（默认 564712547）
    -qp  <qq-pass>    用于发送播报信息的 QQ 密码
'''


def init():
    reload(sys)
    sys.setdefaultencoding(env.CHARSET)

    log.init()

    sdbc = SqliteSDBC(env.DB_PATH)
    sdbc.init(env.SQL_PATH)



def main(help, top, mail_user, mail_pass, qq_user, qq_pass):
    if help:
        log.info(help_info())

    else:
        srcs = [ Cert360(), Nsfocus(), QiAnXin(), RedQueen(), AnQuanKe(), Vas() ]
        for src in srcs:
            msgs = src.cve_msgs()
            to_log(msgs)
            to_page(msgs, top)
            to_notice(msgs, mail_user, mail_pass, qq_user, qq_pass)


def to_log(msgs):
    map(lambda msg : log.info(msg), msgs)


def to_page(msgs, top):
    if msgs:
        page.to_page(top)


def to_notice(msgs, mail_user, mail_pass, qq_user, qq_pass):
    if msgs:
        mail.to_mail(msgs, mail_user, mail_pass)
        qq.to_group(msgs, qq_user, qq_pass)



def get_sys_args(sys_args) :
    help = False
    top = 10
    mail_user = 'threat-broadcast@foxmail.com'
    mail_pass = ''
    qq_user = '564712547'
    qq_pass = ''

    idx = 1
    size = len(sys_args)
    while idx < size :
        try :
            if sys_args[idx] == '-h' :
                help = True

            elif sys_args[idx] == '-top' :
                idx += 1
                top = int(sys_args[idx])

            elif sys_args[idx] == '-mu' :
                idx += 1
                mail_user = sys_args[idx]

            elif sys_args[idx] == '-mp' :
                idx += 1
                mail_pass = sys_args[idx]

            elif sys_args[idx] == '-qu' :
                idx += 1
                qq_user = sys_args[idx]

            elif sys_args[idx] == '-qp' :
                idx += 1
                qq_pass = sys_args[idx]

        except :
            pass
        idx += 1
    return help, top, mail_user, mail_pass, qq_user, qq_pass


if __name__ == '__main__':
    init()
    main(*get_sys_args(sys.argv))



