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
import src.notice.wechat as wechat
import src.utils._git as git



def help_info():
    return '''
    -h                帮助信息
    -top <number>     播报时每个来源最多取最新的前 N 个 CVE（默认 10）
    -ac               自动提交变更到仓库（可自动归档、生成 Github Page，默认关闭）
    -gtk              Github Token，若非空值则使用 Github Actions 发送播报邮件
    -ms  <mail-smtp>  用于发送播报信息的邮箱 SMTP 服务器（默认 smtp.126.com）
    -mu  <mail-user>  用于发送播报信息的邮箱账号（默认 ThreatBroadcast@126.com）
    -mp  <mail-pass>  用于发送播报信息的邮箱密码（部分邮箱为授权码）
    -qu  <qq-user>    用于向 QQ 群发送播报信息的 QQ 账号
    -qp  <qq-pass>    用于发送播报信息的 QQ 密码
'''


def init():
    log.init()
    sdbc = SqliteSDBC(env.DB_PATH)
    sdbc.init(env.SQL_PATH)



def main(help, top, auto_commit, gtk, mail_smtp, mail_user, mail_pass, qq_user, qq_pass):
    if help:
        log.info(help_info())

    else:
        all_cves = {}
        srcs = [ Cert360(), Nsfocus(), QiAnXin(), RedQueen(), AnQuanKe(), Vas() ]
        for src in srcs:
            cves = src.cves()
            if cves:
                to_log(cves)
                all_cves[src] = cves

        if all_cves:
            page.to_page(top)
            mail.to_mail(gtk, all_cves, mail_smtp, mail_user, mail_pass)
            qq.to_group(all_cves, qq_user, qq_pass)
            wechat.to_wechat(all_cves)

            if auto_commit:
                git.auto_commit()



def to_log(cves):
    map(lambda cve : log.info(cve.to_msg()), cves)



def get_sys_args(sys_args) :
    help = False
    top = 10
    auto_commit = False
    gtk = ''
    mail_smtp = 'smtp.qq.com'
    mail_user = 'threatbroadcast@qq.com'
    mail_pass = ''
    qq_user = ''
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

            elif sys_args[idx] == '-ac' :
                auto_commit = True

            elif sys_args[idx] == '-gtk' :
                idx += 1
                gtk = sys_args[idx]

            elif sys_args[idx] == '-ms' :
                idx += 1
                mail_smtp = sys_args[idx]

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
    return help, top, auto_commit, gtk, mail_smtp, mail_user, mail_pass, qq_user, qq_pass


if __name__ == '__main__':
    init()
    main(*get_sys_args(sys.argv))



