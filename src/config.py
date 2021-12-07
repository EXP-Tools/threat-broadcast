#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : EXP
# @Time   : 2020/4/28 21:56
# -----------------------------------------------

import os
import erb.yml as yaml
PRJ_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
CHARSET = 'utf-8'
SETTINGS_PATH = '%s/config/settings.yml' % PRJ_DIR


class Config :

    def __init__(self, settings_path, charset) -> None:
        if os.path.exists(settings_path) :
            with open(settings_path, 'r', encoding=charset) as file:
                context = yaml.load(file.read())
                self.database = context.get('database')
                self.github = context.get('github')
                self.crawler = context.get('crawler')
                self.notify = context.get('notify')


settings = Config(SETTINGS_PATH, CHARSET)