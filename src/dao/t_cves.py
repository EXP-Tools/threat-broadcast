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


class TCvesDao(BaseDao):

    TABLE_NAME = "t_cves"
    SQL_COUNT = "select count(1) from t_cves"
    SQL_TRUNCATE = "truncate table t_cves"
    SQL_INSERT = "insert into t_cves(s_md5, s_src, s_cves, s_title, s_time, s_info, s_url) values (?, ?, ?, ?, ?, ?, ?)"
    SQL_DELETE = "delete from t_cves where 1 = 1 "
    SQL_UPDATE = "update t_cves set s_md5 = ?, s_src = ?, s_cves = ?, s_title = ?, s_time = ?, s_info = ?, s_url = ? where 1 = 1 "
    SQL_SELECT = "select s_md5, s_src, s_cves, s_title, s_time, s_info, s_url from t_cves where 1 = 1 "


    def __init__(self):
        BaseDao.__init__(self)


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
        return bean

