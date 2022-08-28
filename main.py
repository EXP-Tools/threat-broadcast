#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# -----------------------------------------------

import argparse
from src.config import settings
from color_log.clog import log
from pypdm.dbc._sqlite import SqliteDBC

from src.crawler.cert360 import Cert360
from src.crawler.nsfocus import Nsfocus
from src.crawler.qianxin import QiAnXin
from src.crawler.redqueen import RedQueen
from src.crawler.anquanke import AnQuanKe
from src.crawler.vas import Vas
from src.crawler.nvd import NVD
from src.crawler.cnvd import CNVD
from src.crawler.cnnvd import CNNVD
from src.crawler.tenable import Tenable

import src.notice.page as page
import src.notice.mail as mail
import src.notice.qq as qq
import src.notice.wechat as wechat
import src.utils._git as git


GIT_CRAWL_PWD = "3uJtWFf4Vx1S2dSQXJCK"


def args() :
    parser = argparse.ArgumentParser(
        prog='', # 会被 usage 覆盖
        usage='威胁情报播报 - 帮助信息',  
        description='从多个公开的威胁情报来源爬取并整合最新信息',  
        epilog='\r\n'.join([
            '使用示例: ', 
            '  python main.py -t 10 --gtk {GRAPAQL_TOKEN}', 
        ])
    )
    parser.add_argument('-g', '--git', dest='git', type=str, default=GIT_CRAWL_PWD, help='Github Action 的启动密码（避免被 Fork 时别人可以直接运行，导致目标站点被 DDos）')
    parser.add_argument('-t', '--top', dest='top', type=int, default=30, help='播报时每个来源最多取最新的前 N 个 CVE')
    parser.add_argument('-ac', '--auto_commit', dest='auto_commit', action='store_true', default=False, help='自动提交变更到仓库（因使用 Github Actions ，故默认关闭）')
    parser.add_argument('-k', '--gtk', dest='gtk', type=str, default='', help='Github Token，若非空值则使用 Github Actions 发送播报邮件')
    parser.add_argument('-ms', '--mail_smtp', dest='mail_smtp', type=str, default='smtp.qq.com', help='用于发送播报信息的邮箱 SMTP 服务器')
    parser.add_argument('-mu', '--mail_user', dest='mail_user', type=str, default='threatbroadcast@qq.com', help='用于发送播报信息的邮箱账号')
    parser.add_argument('-mp', '--mail_pass', dest='mail_pass', type=str, default='', help='用于发送播报信息的邮箱密码')
    parser.add_argument('-qu', '--qq_user', dest='qq_user', type=str, default='', help='用于向 QQ 群发送播报信息的 QQ 账号')
    parser.add_argument('-qp', '--qq_pass', dest='qq_pass', type=str, default='', help='用于发送播报信息的 QQ 密码')
    return parser.parse_args()


def get_args(args) :
    if args.git != GIT_CRAWL_PWD :
        # Github Action 调用了 -g 参数，若仓库没有设置 secrets.CRAWL_PWD 会赋予为空值
        # 导致验证 Github Action 的 secrets.CRAWL_PWD 失败，爬虫进程终止执行
        # 目的是在仓库被 Fork 时，可以保护目标站点不被 DDos
        exit(0)

    top = args.top or settings.crawler['top']
    auto_commit = args.auto_commit or settings.github['auto_commit']
    gtk = args.gtk or settings.github['gtk']
    mail_smtp = args.mail_smtp or settings.notify['mail_smtp']
    mail_user = args.mail_user or settings.notify['mail_user']
    mail_pass = args.mail_pass or settings.notify['mail_pass']
    qq_user = args.qq_user or settings.notify['qq_user']
    qq_pass = args.qq_pass or settings.notify['qq_pass']
    return [ top, auto_commit, gtk, mail_smtp, mail_user, mail_pass, qq_user, qq_pass ]


def init():
    sdbc = SqliteDBC(options=settings.database)
    sdbc.exec_script(settings.database['sqlpath'])


def main(top, auto_commit, gtk, mail_smtp, mail_user, mail_pass, qq_user, qq_pass):
    all_cves = {}
    srcs = [ 
        Cert360(), 
        Nsfocus(), 
        QiAnXin(), 
        RedQueen(), 
        # AnQuanKe(),   # 已经不做 CVE 分析了
        Vas(), 
        NVD(), 
        # CNVD(),       # 不断升级反爬机制，尊重平台
        CNNVD(), 
        Tenable() 
    ]
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
    for cve in cves :
        log.info(cve.to_msg())



if __name__ == '__main__':
    init()
    main(*get_args(args()))





