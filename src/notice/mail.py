#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 23:29
# @File   : mail.py
# -----------------------------------------------
# 通过邮件发送威胁情报
# -----------------------------------------------

from src.cfg import env
from src.utils import log

MAIL_TPL_PATH = '%s/tpl/mail.tpl' % env.PRJ_DIR


def to_mail(msgs, sender, password):
    pass

def sendEmail(mail_msg):  # 发送邮件
    sender = 'from@163.com' # 发件人
    password = 'password' # 发件人密码
    receiver = 'receiver@163.com' # 收件人
    message = MIMEText(mail_msg, 'plain', 'utf-8') #以文本发送
    message['From'] = sender
    message['To'] = receiver

    subject = '最新CVE列表'
    message['Subject'] = Header(subject, 'utf-8')

    try:
        smtpObj = smtplib.SMTP('smtp.163.com')
        smtpObj.login(sender, password)
        smtpObj.sendmail(sender, receiver, message.as_string())
        print('邮件发送成功')
    except smtplib.SMTPException:
        print('Error: 无法发送邮件')