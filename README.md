# Threat-Broadcast
威胁情报播报

------

## 运行环境

![](https://img.shields.io/badge/Python-2.7%2B-brightgreen.svg)  ![](https://img.shields.io/badge/PyCharm-4.0.4%2B-brightgreen.svg)


## 项目介绍

从以下公开 CVE 情报来源爬取并整合最新威胁情报信息：

- 360：https://cert.360.cn/warning
- 奇安信：https://ti.qianxin.com/advisory/
- 红后：https://redqueen.tj-un.com/IntelHome.html
- 绿盟：http://www.nsfocus.net/vulndb
- 安全客：https://www.anquanke.com/vul
- 斗象：https://vas.riskivy.com/vuln

爬取到的 CVE 情报会作如下处理：

- ~【实时播报】 接收播报信息的 QQ 群： 283212984~
- 【邮件播报】 接受播报信息的邮箱配置： [recv/mail_*.dat](recv)
- 【页面播报】 最新的 TOP10 威胁情报会更新到 [Github Page](https://lyy289065406.github.io/threat-broadcast/)
- 【情报归档】 所有威胁情报会归档到 [sqlite](data/cves.db)


> 因 Smart QQ 已停止服务，暂无法实现 QQ 群推送


## 情报推送源

- ~QQ 群： 283212984~
- 邮箱： ThreatBroadcast@126.com，threatbroadcast@qq.com，threatbroadcast@foxmail.com


## 订阅方式

- ~个人订阅： 加入 QQ 群 283212984 即可~
- 开发者订阅： 因该项目运行在私人服务器，不对所有人开放邮箱订阅；开发者可自行 Fork 项目，通过配置定时任务向自己的邮箱推送即可


## 开发者部署

- 任意找一台 Linux 服务器
- 安装 python 2.7
- 安装 GitPython 模块： `sudo pip install GitPython`
- 安装 git 客户端
- 在 Github Fork 这个仓库： [https://github.com/lyy289065406/auto-planting](https://github.com/lyy289065406/auto-planting)
- 把仓库 checkout 到服务器本地： `git clone https://github.com/{{your_repo}}/auto-planting`
- checkout 的位置任意即可，如： `/tmp/auto-planting`
- 设置使用 SSH 与 Github 连接（避免提交内容时要输入账密），详见 [这里](https://help.github.com/en/articles/connecting-to-github-with-ssh)
- 若设置 SSH 后还要输入密码才能提交，则还需要把仓库的 https 协议改成 ssh，详见 [这里](https://help.github.com/en/articles/changing-a-remotes-url#switching-remote-urls-from-https-to-ssh)
- 修改 crontab 配置文件，设置定时任务： `vim /etc/crontab`
- 设置定时任务命令（每小时）： `0 * * * * root python /tmp/auto-planting/plant.py >> /tmp/err.log 2>&1`
- 注意脚本位置需使用绝对路径，根据实际 checkout 的位置修改即可
- 保存 crontab 配置文件后会自动生效，查看日志： `tail -10f /var/log/cron`


'''
.
├── README.md
├── cache
│   ├── 360.dat
│   ├── AnQuanKe.dat
│   ├── Nsfocus.dat
│   ├── QiAnXin.dat
│   ├── RedQueen.dat
│   └── vas.dat
├── data
│   └── cves.db
├── docs
│   ├── css
│   │   └── page.css
│   └── index.html
├── log
│   ├── err.log
│   ├── run.log
│   └── run.log.2020-04-27
├── main.py
├── recv
│   ├── mail.dat
│   └── qq_group.dat
├── script
│   ├── cves-create.sql
│   └── cves-rollback.sql
├── src
│   ├── __init__.py
│   ├── __init__.pyc
│   ├── bean
│   │   ├── __init__.py
│   │   ├── __init__.pyc
│   │   ├── cve_info.py
│   │   ├── cve_info.pyc
│   │   ├── t_cves.py
│   │   └── t_cves.pyc
│   ├── cfg
│   │   ├── __init__.py
│   │   ├── __init__.pyc
│   │   ├── env.py
│   │   └── env.pyc
│   ├── crawler
│   │   ├── __init__.py
│   │   ├── __init__.pyc
│   │   ├── _base_crawler.py
│   │   ├── _base_crawler.pyc
│   │   ├── anquanke.py
│   │   ├── anquanke.pyc
│   │   ├── cert360.py
│   │   ├── cert360.pyc
│   │   ├── nsfocus.py
│   │   ├── nsfocus.pyc
│   │   ├── qianxin.py
│   │   ├── qianxin.pyc
│   │   ├── redqueen.py
│   │   ├── redqueen.pyc
│   │   ├── vas.py
│   │   └── vas.pyc
│   ├── dao
│   │   ├── __init__.py
│   │   ├── __init__.pyc
│   │   ├── _base.py
│   │   ├── _base.pyc
│   │   ├── t_cves.py
│   │   └── t_cves.pyc
│   ├── notice
│   │   ├── __init__.py
│   │   ├── mail.py
│   │   ├── page.py
│   │   └── qq.py
│   └── utils
│       ├── __init__.py
│       ├── __init__.pyc
│       ├── _sqlite.py
│       ├── _sqlite.pyc
│       ├── log.py
│       └── log.pyc
└── tpl
    ├── html.tpl
    ├── row.tpl
    └── table.tpl
'''


## 版权声明

　[![Copyright (C) EXP,2016](https://img.shields.io/badge/Copyright%20(C)-EXP%202016-blue.svg)](http://exp-blog.com)　[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

- Site: [http://exp-blog.com](http://exp-blog.com) 
- Mail: <a href="mailto:289065406@qq.com?subject=[EXP's Github]%20Your%20Question%20（请写下您的疑问）&amp;body=What%20can%20I%20help%20you?%20（需要我提供什么帮助吗？）">289065406@qq.com</a>


------
