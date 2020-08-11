#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 21:56
# @File   : env.py
# -----------------------------------------------

import os
PRJ_DIR = os.path.dirname(os.path.abspath(__file__)).replace(r'/src/cfg', '').replace(r'\src\cfg', '')

CHARSET = 'utf-8'

SQL_PATH = '%s/script/cves-create.sql' % PRJ_DIR
DB_PATH =  '%s/data/cves.db' % PRJ_DIR

GITHUB_GRAPHQL = 'https://api.github.com/graphql'
GITHUB_REPO = 'threat-broadcast'
GITHUB_REPO_OWNER = 'lyy289065406'
