#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/26 13:14
# @File   : log.py
# -----------------------------------------------
# 日志
# -----------------------------------------------

import traceback
import logging
from logging.handlers import TimedRotatingFileHandler
from src.cfg.env import PRJ_DIR

RUN_LOG = '%s/log/run.log' % PRJ_DIR
ERR_LOG = '%s/log/err.log' % PRJ_DIR


def init(runlog = RUN_LOG, errlog = ERR_LOG):
    """
    初始化日志配置 （只需在程序入口调用一次）
    :return: None
    """

    # 全局配置
    logger = logging.getLogger()
    logger.setLevel("DEBUG")
    BASIC_FORMAT = "%(asctime)s [%(levelname)s] : %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(BASIC_FORMAT, DATE_FORMAT)

    # 输出到控制台的 handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel("DEBUG")
    logger.addHandler(ch)

    # 输出到运行日志文件的 handler
    fh = TimedRotatingFileHandler(filename=runlog, when="MIDNIGHT", interval=1, backupCount=7)
    fh.setFormatter(formatter)
    fh.setLevel("INFO")
    logger.addHandler(fh)

    # 输出到异常日志文件的 handler
    exfh = TimedRotatingFileHandler(filename=errlog, when="MIDNIGHT", interval=1, backupCount=7)
    exfh.setLevel("ERROR")
    exfh.setFormatter(formatter)
    logger.addHandler(exfh)

    # 禁用第三方日志
    # logging.getLogger("requests").setLevel(logging.FATAL)



def debug(msg):
    """
    打印调试信息
    :param msg: 日志信息
    :return: None
    """
    logging.debug(msg)


def info(msg):
    """
    打印正常信息
    :param msg: 日志信息
    :return: None
    """
    logging.info(msg)


def warn(msg):
    """
    打印警告信息
    :param msg: 日志信息
    :return: None
    """
    logging.warning(msg)


def error(msg):
    """
    打印异常信息和异常堆栈
    :param msg: 日志信息
    :return: None
    """
    logging.exception(msg)
    logging.exception(traceback.format_exc())
