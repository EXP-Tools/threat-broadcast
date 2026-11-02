#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/29 23:32
# @File   : t_cves.py
# -----------------------------------------------
# DAO: t_cves
# -----------------------------------------------

from src.bean.t_cves import TCves
from src.dao._base import BaseDao
from src.utils.severity import normalize


class TCvesDao(BaseDao):

    TABLE_NAME = "t_cves"
    SQL_COUNT = "select count(1) from t_cves"
    SQL_TRUNCATE = "delete from t_cves"
    SQL_INSERT = "insert into t_cves(s_md5, s_src, s_cves, s_title, s_time, s_info, s_url, s_severity) values (?, ?, ?, ?, ?, ?, ?, ?)"
    SQL_DELETE = "delete from t_cves where 1 = 1 "
    SQL_UPDATE = "update t_cves set s_md5 = ?, s_src = ?, s_cves = ?, s_title = ?, s_time = ?, s_info = ?, s_url = ?, s_severity = ? where 1 = 1 "
    SQL_SELECT = "select s_md5, s_src, s_cves, s_title, s_time, s_info, s_url, s_severity from t_cves where 1 = 1 "


    def __init__(self):
        BaseDao.__init__(self)


    @staticmethod
    def ensure_schema(conn):
        columns = {row[1] for row in conn.execute('pragma table_info(t_cves)')}
        if 's_severity' not in columns:
            conn.execute("alter table t_cves add column s_severity TEXT(16) NOT NULL DEFAULT ''")
            conn.commit()


    def set_severity(self, conn, cve):
        value = normalize(cve.severity)
        if value:
            conn.execute('update t_cves set s_severity = ? where s_md5 = ? and s_src = ? '
                         'and coalesce(s_severity, \'\') != ?',
                         (value, cve.MD5(), cve.src, value))
            conn.commit()


    def _to_bean(self, row):
        bean = None
        if row:
            bean = TCves()
            bean.md5 = self._to_val(row, 0)
            bean.src = self._to_val(row, 1)
            bean.cves = self._to_val(row, 2)
            bean.title = self._to_val(row, 3)
            bean.time = self._to_val(row, 4)
            bean.info = self._to_val(row, 5)
            bean.url = self._to_val(row, 6)
            bean.severity = normalize(self._to_val(row, 7))
        return bean

