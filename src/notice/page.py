#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 9:37
# @File   : page.py
# -----------------------------------------------
# 从数据库读取最新 CVE 生成 GitHub 播报页面
# -----------------------------------------------

import time
from datetime import datetime, timedelta
from src.cfg import env
from src.utils import log
from src.utils._sqlite import SqliteSDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao

HTML_PATH = '%s/docs/index.html' % env.PRJ_DIR
HTML_TPL_PATH = '%s/tpl/html.tpl' % env.PRJ_DIR
TABLE_TPL_PATH = '%s/tpl/table.tpl' % env.PRJ_DIR
ROW_TPL_PATH = '%s/tpl/row.tpl' % env.PRJ_DIR


def to_page(top_limit = 10):
    today = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    tormorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d') 

    html_tpl, table_tpl, row_tpl = load_tpl()
    sdbc = SqliteSDBC(env.DB_PATH)
    conn = sdbc.conn()

    tables = []
    srcs = query_srcs(conn)
    for src in srcs:
        cves = query_cves(conn, src, top_limit)

        rows = []
        for cve in cves:
            row = row_tpl % {
                'md5': cve.md5,
                'id': cve.cves,
                'time': cve.time,
                'new_flag': ' <img src="imgs/new.gif" />' if (cve.time.startswith(today) or cve.time.startswith(yesterday) or cve.time.startswith(tormorrow)) else '', 
                'title': cve.title,
                'url': cve.url
            }
            rows.append(row)

        table = table_tpl % {
            'src': cves[0].src,
            'top': top_limit,
            'rows': '\n'.join(rows)
        }
        tables.append(table)

    html = html_tpl % {
        'datetime': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) ,
        'table': '\n\n'.join(tables)
    }
    sdbc.close()

    create_html(html)



def load_tpl():
    with open(HTML_TPL_PATH, 'r', encoding=env.CHARSET) as file:
        html_tpl = file.read()

    with open(TABLE_TPL_PATH, 'r', encoding=env.CHARSET) as file:
        table_tpl = file.read()

    with open(ROW_TPL_PATH, 'r', encoding=env.CHARSET) as file:
        row_tpl = file.read()

    return html_tpl, table_tpl, row_tpl



def create_html(html):
    with open(HTML_PATH, 'w', encoding=env.CHARSET) as file:
        file.write(html)



def query_srcs(conn):
    sql = 'select %s from %s group by %s' % (TCves.s_src, TCves.table_name, TCves.s_src)
    srcs = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        for row in rows:
            srcs.append(row[0])
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return srcs



def query_cves(conn, src, limit):
    dao = TCvesDao()
    where = "and %s = '%s' order by %s desc limit %d" % (TCves.s_src, src, TCves.s_time, limit)
    sql = TCvesDao.SQL_SELECT + where
    beans = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        for row in rows:
            bean = dao._to_bean(row)
            beans.append(bean)
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return beans
