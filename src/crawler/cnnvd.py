#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/12/01 23:21
# @File   : cnnvd.py
# -----------------------------------------------
# cnnvd: http://www.cnnvd.org.cn/
# -----------------------------------------------

from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils import log
import requests
import re
import time
from lxml import etree


class CNNVD(BaseCrawler):

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '国家信息安全漏洞库（CNNVD）'
        self.name_en = 'CNNVD'
        self.home_page = 'http://www.cnnvd.org.cn/'
        self.url_list = 'http://www.cnnvd.org.cn/web/vulnerability/querylist.tag'
        self.url_cve = 'http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD='


    def NAME_CH(self):
        return self.name_ch


    def NAME_EN(self):
        return self.name_en


    def HOME_PAGE(self):
        return self.home_page


    def get_cves(self, limit = 6):
        response = requests.get(
            self.url_list,
            headers = self.headers(), 
            timeout = self.timeout
        )
        response.encoding = 'utf-8'

        cves = []
        if response.status_code == 200:
            ids = re.findall(r'ldxqById\.tag\?CNNVD=([^"]+)">', response.text)
            for id in ids :
                cve = self.to_cve(id)
                if cve.is_vaild():
                    cves.append(cve)
                    # log.debug(cve)
        else:
            log.warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves


    def to_cve(self, id):
        cve = CVEInfo()
        cve.id = id
        cve.src = self.NAME_CH()
        cve.url = self.url_cve + id
        self.get_cve_info(cve, cve.url)
        return cve


    def get_cve_info(self, cve, url) :
        try :
            response = requests.get(
                url,
                headers = self.headers(), 
                timeout = self.timeout
            )
            response.encoding = 'utf-8'

            if response.status_code == 200:
                html = etree.HTML(response.text)
                body = html.xpath("./body")
                div1 = body[0].xpath("./div[contains(@class, 'container') and contains(@class, 'm_t_10')]")
                div2 = div1[0].xpath("./div[contains(@class, 'container') and contains(@class, 'm_t_20')]")
                div3 = div2[0].xpath("./div[contains(@class, 'fl') and contains(@class, 'w770')]")
                div4 = div3[0].xpath("./div[contains(@class, 'detail_xq') and contains(@class, 'w770')]")
                title = div4[0].xpath("./h2")[0].text.strip()
                cve.title = title

                div5 = div3[0].xpath("./div[@class='d_ldjj']")
                p_list = div5[0].xpath("./p[@style='text-indent:2em']")
                for p in p_list :
                    cve.info += p.text.strip()
                
                cve.id = "%s (%s)" % (cve.id, re.findall(r'cvename\.cgi\?name=([^"]*)"', response.text)[0].strip())
                cve.time = re.findall(r'qstartdateXq=([^"]*)"', response.text)[0].strip() + time.strftime(" %H:%M:%S", time.localtime())
        except :
            pass  # 漏洞信息页面不存在

        time.sleep(1)

