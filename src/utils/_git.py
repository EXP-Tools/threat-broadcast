#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/5/1 22:31
# @File   : _git.py
# -----------------------------------------------
# git 自动提交变更
# -----------------------------------------------

import os
import sys
import json
import time
import git
from python_graphql_client import GraphqlClient
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



# 通过 GraphQL 接口查询所有 Issue 标题
# https://developer.github.com/v4/object/repository/
# issues (IssueConnection!)
def query_issues(github_token, owner=env.GITHUB_REPO_OWNER, repo=env.GITHUB_REPO, iter=100):
    titles = []
    client = GraphqlClient(endpoint=env.GITHUB_GRAPHQL)
    has_next_page = True
    next_cursor = None
    while has_next_page:
        data = client.execute(
            query=_to_graphql(next_cursor, owner, repo, iter),
            headers={ "Authorization": "Bearer {}".format(github_token) },
        )
        # log.debug(json.dumps(data))

        issues = data["data"]["repository"]["issues"]
        for issue in issues["edges"] :
            is_closed = issue["node"]["closed"]
            if not is_closed :
                title = issue["node"]["title"]
                titles.append(title)

        has_next_page = issues["pageInfo"]["hasNextPage"]
        next_cursor = issues["pageInfo"]["endCursor"]
    return titles



def _to_graphql(next_cursor, owner, repo, iter):
    return ("""
query {
    repository(owner: "%s", name: "%s") {
        issues(orderBy:{field: UPDATED_AT, direction: DESC}, labels: null, first: %i, after: NEXT) {
            edges {
                node {
                    title
                    closed
                }
            }
            pageInfo {
                hasNextPage
                endCursor
            }
        }
    }
}
""" % (owner, repo, iter)).replace(
        "NEXT", '"{}"'.format(next_cursor) if next_cursor else "null"
    )