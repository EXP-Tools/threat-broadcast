#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 23:29
# @File   : mail.py
# -----------------------------------------------
# 通过邮件发送威胁情报
# -----------------------------------------------

import os
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from src.cfg import env
from src.utils import log



MAIL_TPL_PATH = '%s/tpl/mail.tpl' % env.PRJ_DIR
RECV_DIR = '%s/recv' % env.PRJ_DIR


def to_mail(cves, smtp, sender, password):
    log.info('[邮件] 正在推送威胁情报...')

    content = format_content(cves)
    email = MIMEText(content, 'html', env.CHARSET)     # 以 html 格式发送邮件内容
    email['From'] = sender
    receivers = load_receivers()
    email['To'] = receivers
    log.info('[邮件] 收件人清单： %s' % receivers)

    subject = '威胁情报播报'
    email['Subject'] = Header(subject, 'utf-8')

    try:
        smtpObj = smtplib.SMTP(smtp)
        smtpObj.login(sender, password)
        smtpObj.sendmail(sender, receivers, email.as_string())
        log.info('[邮件] 推送威胁情报成功')

    except:
        log.error('[邮件] 推送威胁情报失败')


def format_content(cves):
    return '测试2'


def load_receivers():
    recvs = []
    for dirPath, dirNames, fileNames in os.walk(RECV_DIR):
        for fileName in fileNames:
            if fileName.startswith('mail') and fileName.endswith('.dat'):
                filePath = '%s/%s' % (RECV_DIR, fileName)
                with open(filePath, 'r') as file:
                    lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        if (not line) or line.startswith('#'):
                            continue
                        recvs.append(line)
    return ';'.join(set(recvs))