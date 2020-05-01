#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/5/1 22:31
# @File   : _git.py
# -----------------------------------------------
# git 自动提交变更
# -----------------------------------------------

import time
import git
from src.cfg import env
from src.utils import log


# 需要手动把仓库的 HTTPS 协议修改成 SSH
# git remote set-url origin git@github.com:lyy289065406/threat-broadcast.git
def auto_commit():
    log.info('正在提交变更...')
    try:
        repo = git.Repo(env.PRJ_DIR)
        repo.git.add('*')
        repo.git.commit(m='[Threat-Broadcast] %s' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
        repo.git.push()
        log.info('提交变更成功')

    except:
        log.error('提交变更失败')



