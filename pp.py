#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/25 22:17
# @File   : main.py
# -----------------------------------------------

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import ast


def get_cookies():
    chrome_options = Options()
    # 加上下面两行，解决报错
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(chrome_options=chrome_options)
    driver.get("https://www.cnvd.org.cn/flaw/list.htm?max=20&offset=20")#设置每次ChromeDriver访问的初始页面用来更新cookie，以绕过cnvd爬虫限制
    cj = driver.get_cookies()
    cookie = ''
    for c in cj:
        cookie += "'"+c['name'] + "':'" + c['value'] + "',"
    cookie = ast.literal_eval('{'+cookie+'}')
    driver.quit()
    return cookie

if __name__ == '__main__':
    cookie = get_cookies()
    print(cookie)

