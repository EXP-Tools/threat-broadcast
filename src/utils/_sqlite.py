#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/29 22:14
# @File   : _sqlite.py
# -----------------------------------------------
# Sqlite 数据库接口
# -----------------------------------------------

from src.cfg import env
from src.utils import log
import sqlite3


class SqliteDBC:
    """
    Sqlite 数据库封装类
    """

    def __init__(self, dbpath='test.db'):
        """
        构造函数
        :param dbname: 数据库路径
        """
        self.dbpath = dbpath
        self._conn = None


    def conn(self):
        """
        连接到数据库
        :return: 数据库连接（失败返回 None）
        """
        if not self._conn:
            try:
                self._conn = sqlite3.connect(database = self.dbpath)
                self._conn.text_factory = str
            except:
                log.error("连接数据库 [%s] 失败" % self.dbpath)
        return self._conn


    def close(self):
        """
        断开数据库连接
        :return: 是否断开成功
        """
        is_ok = False
        if self._conn:
            try:
                self._conn.close()
                self._conn = None
                is_ok = True
            except:
                log.error("断开数据库 [%s] 失败" % self.dbpath)
        return is_ok


    def reconn(self):
        """
        重连数据库
        :return: 数据库连接（失败返回 None）
        """
        self.close()
        return self.conn()


    def commit(self):
        """
        提交事务
        :return: 是否提交成功
        """
        is_ok = False
        if self._conn:
            try:
                self._conn.commit()
                is_ok = True
            except:
                log.error("提交事务到数据库 [%s] 失败" % self.dbpath)
        return is_ok


    def init(self, sql_script):
        """
        初始化数据库
        :param sql_script: 建库脚本（注意控制好数据表是否存在）
        :return: 是否初始化成功
        """
        if self.conn():
            try:
                data = ""
                with open(sql_script, "r", encoding=env.CHARSET) as file:
                    data = file.read()

                if data:
                    cursor = self._conn.cursor()
                    sqls = data.split(";")
                    for sql in sqls:
                        sql = sql.strip()
                        if sql:
                            cursor.execute(sql)
                    cursor.close()
            except:
                log.error("初始化数据库 [%s] 失败" % self.dbpath)
            self.close()

