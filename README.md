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
- ~【实时播报】 接收播报信息的微信公众号： EXP技术分享平台~
- 【邮件播报】 接受播报信息的邮箱配置： [recv/mail_*.dat](recv/mail.dat)
- 【页面播报】 最新的 TOP10 威胁情报会更新到 [Github Page](https://lyy289065406.github.io/threat-broadcast/)
- 【情报归档】 所有威胁情报会归档到 [sqlite](data/cves.db)


> 因 Smart QQ 已停止服务，暂无法实现 QQ 群推送

<details>
<summary>播报效果</summary>
<br/>

![](docs/email.png)

</details>


## 推送源

- ~QQ 群： 283212984~
- 邮箱： 
<br/>　　ThreatBroadcast@126.com
<br/>　　threatbroadcast@qq.com
<br/>　　threatbroadcast@foxmail.com


## 订阅方式

- ~【个人订阅】 加入 QQ 群： 283212984~
- ~【个人订阅】 加入微信公众号： EXP技术分享平台~
- 【个人订阅】 在 [Issues](issues) 留下你接收情报用的邮箱，我会不定时处理
- 【开发者订阅】 因该项目运行在私人服务器，不对所有人开放邮箱订阅；开发者可自行 Fork 项目，通过配置定时任务向自己的邮箱推送即可


## 开发者部署

### 安装

- 任意找一台 Linux 服务器
- 安装 python 2.7
- 把仓库 checkout 到服务器本地： `git clone https://github.com/lyy289065406/threat-broadcast`


## 配置定时任务

- 修改 crontab 配置文件，设置定时任务： `vim /etc/crontab`
- 设置定时任务命令（每小时）： `0 * * * * root python ${workspace}/threat-broadcast/main.py [-any_args]`
- 注意脚本位置需使用绝对路径，根据实际 checkout 的位置修改即可
- 保存 crontab 配置文件后会自动生效，查看日志： `tail -10f /var/log/cron`

> 程序运行参数可通过 [`main.py -h`](main.py) 查看帮助文档


## 自动生成 Github Page 播报页面

- 安装 git 命令行客户端
- 安装 GitPython 模块： `pip install GitPython`
- 打开项目目录： `cd ${workspace}/threat-broadcast`
- 设置使用 SSH 与 Github 连接（避免提交内容时要输入账密），详见 [这里](https://help.github.com/en/articles/connecting-to-github-with-ssh)
- 若设置 SSH 后还要输入密码才能提交，则还需要把仓库的 https 协议改成 ssh，详见 [这里](https://help.github.com/en/articles/changing-a-remotes-url#switching-remote-urls-from-https-to-ssh)
- [`main.py`](main.py) 添加运行参数 `-ac` 可自动提交变更到仓库


> 只要爬取到新的威胁情报则会刷新 [`docs/index.html`](docs/index.html)，将其提交到仓库会自动更新 [Github Page](https://lyy289065406.github.io/threat-broadcast/)


## 目录说明

```
threat-broadcast
├── README.md ............................... [项目说明]
├── main.py ................................. [程序运行入口]
├── cache ................................... [威胁情报缓存]
├── data
│   └── cves.db ............................. [sqlite: 威胁情报归档]
├── docs .................................... [Github Page 威胁情报总览]
├── recv
│   ├── mail.dat ............................ [接收威胁情报的邮箱]
│   └── qq_group.dat ........................ [接收威胁情报的 QQ 群]
├── src ..................................... [项目源码]
├── script .................................. [数据库脚本]
├── tpl ..................................... [模板文件]
└── log ..................................... [项目日志]
```


## 版权声明

　[![Copyright (C) EXP,2016](https://img.shields.io/badge/Copyright%20(C)-EXP%202016-blue.svg)](http://exp-blog.com)　[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

- Site: [http://exp-blog.com](http://exp-blog.com) 
- Mail: <a href="mailto:289065406@qq.com?subject=[EXP's Github]%20Your%20Question%20（请写下您的疑问）&amp;body=What%20can%20I%20help%20you?%20（需要我提供什么帮助吗？）">289065406@qq.com</a>


------
