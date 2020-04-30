#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/29 23:31
# @File   : _base.py
# -----------------------------------------------
# 数据访问对象：基类
# -----------------------------------------------

from src.utils import log


class BaseDao:
    """
    Dao 基类
    """

    # TODO 需子类实现
    TABLE_NAME = ""
    SQL_COUNT = ""
    SQL_TRUNCATE = ""
    SQL_INSERT = ""
    SQL_DELETE = ""
    SQL_UPDATE = ""
    SQL_SELECT = ""
    CHARSET = "utf-8"

    def __init__(self):
        pass


    def count(self, conn):
        """
        统计行数
        :param conn: 数据库连接
        :return: 表行数
        """
        cnt = 0
        try:
            cursor = conn.cursor()
            cursor.execute(self.SQL_COUNT)
            cnt = cursor.fetchone()[0]
            cursor.close()
        except:
            log.error("统计表 [%s] 行数失败" % self.TABLE_NAME)
        return cnt


    def truncate(self, conn):
        """
        清空表
        :param conn: 数据库连接
        :return: 是否清空成功
        """
        is_ok = False
        try:
            cursor = conn.cursor()
            cursor.execute(self.SQL_TRUNCATE)
            conn.commit()
            cursor.close()
            is_ok = True
        except:
            log.error("清空表 [%s] 失败" % self.TABLE_NAME)
        return is_ok


    def insert(self, conn, bean):
        """
        插入单条数据
        :param conn: 数据库连接
        :param bean: 数据模型实例
        :return: 是否插入成功
        """
        is_ok = False
        try:
            cursor = conn.cursor()
            params = bean.params()
            cursor.execute(self.SQL_INSERT, params)
            conn.commit()
            cursor.close()
            is_ok = True
        except:
            log.error("插入数据到表 [%s] 失败" % self.TABLE_NAME)
        return is_ok


    def insert_all(self, conn, beans):
        """
        插入多条数据
        :param conn: 数据库连接
        :param beans: 数据模型实例队列
        :return: 成功插入个数
        """
        cnt = 0
        try:
            cursor = conn.cursor()
            for bean in beans:
                try:
                    params = bean.params()
                    cursor.execute(self.SQL_INSERT, params)
                    cnt += 1
                except:
                    log.error("插入数据到表 [%s] 失败" % self.TABLE_NAME)
            conn.commit()
            cursor.close()
        except:
            log.error("插入数据集到表 [%s] 失败" % self.TABLE_NAME)
        return cnt


    def delete(self, conn, wheres={}):
        """
        删除数据
        :param conn: 数据库连接
        :param wheres: 条件键值对, 要求键值包含操作符，如： { 'column1 like': 'xyz', 'column2 =': 'abc' }
        :return: 是否删除成功
        """
        is_ok = False
        try:
            cursor = conn.cursor()
            sql = self._append(self.SQL_DELETE, wheres.keys())
            cursor.execute(sql, wheres.values())
            conn.commit()
            cursor.close()
            is_ok = True
        except:
            log.error("从表 [%s] 删除数据失败" % self.TABLE_NAME)
        return is_ok


    def update(self, conn, bean):
        """
        更新数据
        :param conn: 数据库连接
        :param bean: 数据模型实例
        :return: 是否更新成功
        """
        is_ok = False
        try:
            cursor = conn.cursor()
            sql = self._append(self.SQL_UPDATE, ["%s = " % bean.i_id])
            params = bean.params() + (bean.id,)
            cursor.execute(sql, params)
            conn.commit()
            cursor.close()
            is_ok = True
        except:
            log.error("更新数据到表 [%s] 失败" % self.TABLE_NAME)
        return is_ok


    def query_all(self, conn):
        """
        查询表中所有数据
        :param conn: 数据库连接
        :return: 数据模型实例队列（失败返回 [] ，不会为 None）
        """
        return self.query_some(conn)


    def query_some(self, conn, wheres={}):
        """
        查询表中部分数据
        :param conn: 数据库连接
        :param wheres: 条件键值对, 要求键值包含操作符，如： { 'column1 like': 'xyz', 'column2 =': 'abc' }
        :return: 数据模型实例队列（失败返回 [] ，不会为 None）
        """
        beans = []
        try:
            cursor = conn.cursor()
            sql = self._append(self.SQL_SELECT, wheres.keys())
            cursor.execute(sql, wheres.values())
            rows = cursor.fetchall()
            for row in rows:
                bean = self._to_bean(row)
                beans.append(bean)
            cursor.close()
        except:
            log.error("从表 [%s] 查询数据失败" % self.TABLE_NAME)
        return beans


    def query_one(self, conn, wheres={}):
        """
        查询表中一条数据
        :param conn: 数据库连接
        :param wheres: 条件键值对, 要求键值包含操作符，如： { 'column1 like': 'xyz', 'column2 =': 'abc' }
        :return: 数据模型实例队列（若多个满足则返回第 1 个，没有满足则返回 None）
        """
        bean = None
        try:
            cursor = conn.cursor()
            sql = self._append(self.SQL_SELECT, wheres.keys())
            cursor.execute(sql, wheres.values())
            row = cursor.fetchone()
            bean = self._to_bean(row)
            conn.commit()
            cursor.close()
        except:
            log.error("从表 [%s] 查询数据失败" % self.TABLE_NAME)
        return bean


    def _append(self, sql, keys):
        """
        追加 where 条件到 sql, 条件之间只为 and 关系（目的只是支持简单的数据库操作）
        :param sql: 语句
        :param keys: 条件键值集合, 要求键值包含操作符，如： [ 'column1 like'， 'column2 =' ]
        :return: 追加 where 条件后的 sql
        """
        _sql = sql
        if keys:
            for key in keys:
                _sql = " ".join((_sql, "and", key, " ?"))  # ? 是 sql 占位符，目的是防注入
        return _sql


    def _to_bean(self, row):
        """
        把数据库查询的单行结果转换成模型实例对象
        :param row: 单行查询结果
        :return: 模型实例对象
        """
        # 需子类实现
        return row


    def _to_val(self, row, idx):
        """
        把 unicode 编码的字符串转换成 utf8
        :param row: 行对象
        :param idx: 列索引
        :return: 列值（utf8 编码）
        """
        val = None
        try:
            val = row[idx]
            if val is not None and isinstance(val, unicode):
                val = val.encode(self.CHARSET)
        except:
            pass
        return val

