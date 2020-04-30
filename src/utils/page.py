#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 9:37
# @File   : page.py
# -----------------------------------------------

from src.cfg import env
from src.utils import log
from src.utils._sqlite import SqliteSDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao

HTML_PATH = '%s/docs/index.html' % env.PRJ_DIR
HTML_TPL_PATH = '%s/tpl/page.tpl' % env.PRJ_DIR
TABLE_TPL_PATH = '%s/tpl/table.tpl' % env.PRJ_DIR
ROW_TPL_PATH = '%s/tpl/row.tpl' % env.PRJ_DIR


def to_page():
    sdbc = SqliteSDBC(env.DB_PATH)
    conn = sdbc.conn()

    srcs = query_srcs(conn)
    for src in srcs:
        cves = query_some(conn, src, 5)



    sdbc.close()



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


def query_some(conn, src, limit):
    dao = TCvesDao()
    where = "and %s = '%s' order by rowid desc limit %d" % (TCves.s_src, src, limit)
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