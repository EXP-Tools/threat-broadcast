#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 9:37
# @File   : page.py
# -----------------------------------------------
# 从数据库读取最新 CVE 生成 GitHub 播报页面
# -----------------------------------------------

import time
from html import escape
from datetime import datetime, timedelta
import src.config as config
from color_log.clog import log
from pypdm.dbc._sqlite import SqliteDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao

HTML_PATH = '%s/docs/index.html' % config.PRJ_DIR
HTML_TPL_PATH = '%s/tpl/html.tpl' % config.PRJ_DIR
TABLE_TPL_PATH = '%s/tpl/table.tpl' % config.PRJ_DIR
ROW_TPL_PATH = '%s/tpl/row.tpl' % config.PRJ_DIR


def to_page(top_limit = 10, active_sources=None):
    today = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    tormorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d') 

    html_tpl, table_tpl, row_tpl = load_tpl()
    sdbc = SqliteDBC(options=config.settings.database)
    conn = sdbc.conn()

    tables = []
    srcs = query_srcs(conn, active_sources)
    for src in srcs:
        cves = query_cves(conn, src, top_limit)
        if not cves:
            continue

        rows = []
        for cve in cves:
            row = row_tpl % {
                'md5': escape(cve.md5 or ''),
                'id': escape(cve.cves or ''),
                'time': escape(cve.time or ''),
                'new_flag': ' <img src="imgs/new.gif" />' if (cve.time.startswith(today) or cve.time.startswith(yesterday) or cve.time.startswith(tormorrow)) else '', 
                'title': escape(cve.title or ''),
                'url': escape(cve.url or '')
            }
            rows.append(row)

        table = table_tpl % {
            'src': escape(cves[0].src or ''),
            'top': top_limit,
            'rows': '\n'.join(rows)
        }
        tables.append(table)

    html = html_tpl % {
        'datetime': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) ,
        'source_status': format_source_status(),
        'table': '\n\n'.join(tables)
    }
    sdbc.close()

    create_html(html)


def format_source_status():
    disabled = config.settings.crawler.get('disabled_sources', {})
    if not disabled:
        return ''
    rows = ['<li>%s：%s</li>' % (escape(name), escape(reason))
            for name, reason in disabled.items()]
    return ('<details><summary>暂停更新的来源（已从页面隐藏）</summary>'
            '<ul>%s</ul></details>' % ''.join(rows))



def load_tpl():
    with open(HTML_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        html_tpl = file.read()

    with open(TABLE_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        table_tpl = file.read()

    with open(ROW_TPL_PATH, 'r', encoding=config.CHARSET) as file:
        row_tpl = file.read()

    return html_tpl, table_tpl, row_tpl



def create_html(html):
    with open(HTML_PATH, 'w', encoding=config.CHARSET, newline='\n') as file:
        file.write(html)



def query_srcs(conn, active_sources=None):
    sql = 'select %s from %s' % (TCves.s_src, TCves.table_name)
    params = []
    if active_sources is not None:
        if not active_sources:
            return []
        sql += ' where %s in (%s)' % (TCves.s_src, ','.join('?' for _ in active_sources))
        params.extend(active_sources)
    sql += ' group by %s' % TCves.s_src
    max_age = config.settings.crawler.get('max_age_days', 90)
    if max_age:
        sql += ' having max(date(%s)) >= date(\'now\', ?)' % TCves.s_time
        params.append('-%d days' % max_age)
    srcs = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        for row in rows:
            srcs.append(row[0])
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return srcs



def query_cves(conn, src, limit):
    dao = TCvesDao()
    where = "and %s = ? order by %s desc limit ?" % (TCves.s_src, TCves.s_time)
    sql = TCvesDao.SQL_SELECT + where
    beans = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (src, limit))
        rows = cursor.fetchall()
        for row in rows:
            bean = dao._to_bean(row)
            beans.append(bean)
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return beans
