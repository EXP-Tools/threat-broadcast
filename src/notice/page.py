#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/30 9:37
# @File   : page.py
# -----------------------------------------------
# 从数据库读取最新 CVE 生成 GitHub 播报页面
# -----------------------------------------------

import json
from html import escape
from datetime import datetime, timezone
import src.config as config
from color_log.clog import log
from pypdm.dbc._sqlite import SqliteDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao
from src.utils.severity import LABELS, normalize

HTML_PATH = '%s/docs/index.html' % config.PRJ_DIR
HTML_TPL_PATH = '%s/tpl/html.tpl' % config.PRJ_DIR
TABLE_TPL_PATH = '%s/tpl/table.tpl' % config.PRJ_DIR
ROW_TPL_PATH = '%s/tpl/row.tpl' % config.PRJ_DIR


def to_page(top_limit=10, active_sources=None):
    now = datetime.now(timezone.utc)
    html_tpl, table_tpl, row_tpl = load_tpl()
    sdbc = SqliteDBC(options=config.settings.database)
    records, initial = [], []
    try:
        conn = sdbc.conn()
        for src in query_srcs(conn, active_sources):
            cves = query_cves(conn, src, -1, recent_only=True)
            source_records = []
            for cve in cves:
                source_records.append({
                    'id': cve.cves or '', 'md5': cve.md5 or '',
                    'title': cve.title or '', 'source': cve.src or '',
                    'time': cve.time or '', 'url': cve.url or '',
                    'severity': normalize(cve.severity),
                })
            records.extend(source_records)
            initial.extend(source_records[:max(0, top_limit)])
    finally:
        sdbc.close()
    records.sort(key=lambda record: record['time'], reverse=True)
    initial.sort(key=lambda record: record['time'], reverse=True)
    rows = []
    for record in initial:
        values = {key: escape(str(value)) for key, value in record.items()}
        values['severity'] = LABELS[record['severity']]
        values['severity_class'] = record['severity'].lower() or 'unknown'
        rows.append(row_tpl % values)
    sources = sorted({record['source'] for record in records})
    records_json = json.dumps(records, ensure_ascii=False, separators=(',', ':')).replace('<', chr(92) + 'u003c')
    create_html(html_tpl % {
        'datetime': now.strftime('%Y-%m-%d %H:%M:%S'),
        'generated_iso': now.isoformat(),
        'window_days': config.settings.crawler.get('max_age_days', 90) or 90,
        'total_count': len(records),
        'high_count': sum(record['severity'] in ('CRITICAL', 'HIGH') for record in records),
        'source_count': len(sources),
        'source_options': ''.join('<option value="%s">%s</option>' % (escape(src), escape(src)) for src in sources),
        'source_status': format_source_status(),
        'top_limit': top_limit,
        'table': table_tpl % {'rows': '\n'.join(rows)},
        'records_json': records_json,
    })


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



def query_cves(conn, src, limit, recent_only=False):
    dao = TCvesDao()
    where = "and %s = ? order by %s desc limit ?" % (TCves.s_src, TCves.s_time)
    params = [src]
    if recent_only:
        days = config.settings.crawler.get('max_age_days', 90) or 90
        where = "and %s = ? and date(%s) >= date('now', ?) order by %s desc limit ?" % (
            TCves.s_src, TCves.s_time, TCves.s_time)
        params.append('-%d days' % days)
    params.append(limit)
    sql = TCvesDao.SQL_SELECT + where
    beans = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        for row in rows:
            bean = dao._to_bean(row)
            beans.append(bean)
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return beans
