#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 23:29
# @File   : mail.py
# -----------------------------------------------
# 通过邮件发送威胁情报
# -----------------------------------------------

import os
import re
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from src.cfg import env
from src.utils import log
from src.utils import _git

MAIL_TPL_PATH = '%s/tpl/mail.tpl' % env.PRJ_DIR
MAIL_RECV_DIR = '%s/recv' % env.PRJ_DIR

MAIL_CONTENT_CACHE = '%s/cache/mail_content.dat' % env.PRJ_DIR
MAIL_RECV_CACHE = '%s/cache/mail_recvs.dat' % env.PRJ_DIR


def to_mail(gtk, cves, smtp, sender, password):
    content = format_content(cves)
    receivers = load_local_receivers()
    if gtk:
        log.info('[邮件] 正在通过 Github Actions 推送威胁情报...')
        recvs = load_issue_receivers(gtk)
        recvs.update(receivers)
        to_cache(','.join(recvs), MAIL_RECV_CACHE)
        to_cache(content, MAIL_CONTENT_CACHE)

    else:
        log.info('[邮件] 正在推送威胁情报...')
        email = MIMEText(content, 'html', env.CHARSET)     # 以 html 格式发送邮件内容
        email['From'] = sender
        email['To'] = ', '.join(receivers)                  # 此处收件人列表必须为逗号分隔的 str
        log.info('[邮件] 收件人清单： %s' % receivers)
        subject = '威胁情报播报'
        email['Subject'] = Header(subject, 'utf-8')

        try:
            smtpObj = smtplib.SMTP(smtp)
            smtpObj.login(sender, password)
            smtpObj.sendmail(sender, receivers, email.as_string())  # 此处收件人列表必须为 list
            log.info('[邮件] 推送威胁情报成功')
        except:
            log.error('[邮件] 推送威胁情报失败')


def format_content(cves):
    src_tpl = '    <li><font color="red">%(cnt)d</font>条由 [<a href="%(url)s">%(src)s</a>] 提供</li>'
    mail_tpl =  '''
<h3>发现最新威胁情报<font color="red">%(total)d</font>条：</h3>
<ul>
%(src_infos)s
</ul>
<h3>详细漏洞清单如下：</h3>
<br/>
%(cve_infos)s

<br/><br/>
++++++++++++++++++++++++++++++++++++++++++++++
<br/>
<font color="red">【情报收集与播报支持】</font> https://lyy289065406.github.io/threat-broadcast/
'''
    src_infos = []
    cve_infos = []
    total = 0
    for src, _cves in cves.items():
        cnt = len(_cves)
        total += cnt
        src_infos.append(src_tpl % {
            'cnt': cnt,
            'url': src.HOME_PAGE(),
            'src': src.NAME_CH()
        })
        for cve in _cves:
            cve_infos.append(cve.to_html())

    content = mail_tpl % {
        'total': total,
        'src_infos': '\n'.join(src_infos),
        'cve_infos': '\n'.join(cve_infos)
    }
    return content


def load_local_receivers():
    recvs = set()
    for dirPath, dirNames, fileNames in os.walk(MAIL_RECV_DIR):
        for fileName in fileNames:
            if fileName.startswith('mail') and fileName.endswith('.dat'):
                filePath = '%s/%s' % (MAIL_RECV_DIR, fileName)
                with open(filePath, 'r', encoding=env.CHARSET) as file:
                    lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        if (not line) or line.startswith('#'):
                            continue
                        recvs.add(line)
    return list(recvs)


def load_issue_receivers(gtk):
    recvs = set()
    try: 
        issues = _git.query_issues(gtk)
        for issue in issues :
            ptn = re.compile(r'([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+)')
            emails = ptn.findall(issue)
            for email in emails:
                recvs.add(email[0])
    except:
        log.error('获取 Issue 的邮箱失败（国内 GraphQL 接口不稳定）')
    return recvs


def to_cache(date, filepath):
    with open(filepath, 'w+', encoding=env.CHARSET) as file:
        file.write(date)
