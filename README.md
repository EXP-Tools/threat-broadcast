# Threat-Broadcast

> 聚合公开漏洞情报，归档到 SQLite，并生成可筛选的 GitHub Pages 情报看板。

[![CI](https://github.com/EXP-Tools/threat-broadcast/actions/workflows/autorun.yml/badge.svg)](https://github.com/EXP-Tools/threat-broadcast/actions/workflows/autorun.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/EXP-Tools/threat-broadcast?style=social)](https://github.com/EXP-Tools/threat-broadcast)

**[查看情报看板](https://exp-tools.github.io/threat-broadcast/)** · [采集与验证任务](https://github.com/EXP-Tools/threat-broadcast/actions/workflows/autorun.yml) · [反馈问题](https://github.com/EXP-Tools/threat-broadcast/issues)

## 功能

- 聚合安全厂商、国家漏洞库、AI 发现披露和公开漏洞 Wiki，保存原文链接。
- 按漏洞来源、等级、时间和关键词组合筛选；等级支持下拉连续多选。
- 展示严重、高危、中危、低危、无危害或未知等级，不推测缺失评分。
- SQLite 持久归档，结合数据库和缓存去重，避免缓存裁剪后重复入库。
- 默认每 3 小时自动采集；失效来源可停用，过期情报从页面隐藏，历史归档保留。
- 页面为静态 HTML/CSS/JavaScript，无需后端或第三方 CDN。

## 情报来源

### 默认启用

| 来源 | 采集范围与时间 | 等级依据 |
| --- | --- | --- |
| [绿盟](https://www.nsfocus.net/) | HTTPS JSON 接口返回的最新漏洞，使用来源更新时间 | 当前公开接口未提供，显示未知 |
| [NVD](https://nvd.nist.gov/) | 官方 CVE API 2.0，最近 7 天内最新的 10 条记录 | 优先采用 CVSS 4.0、3.1、3.0、2.0，同版本优先 Primary 评分 |
| [Tenable (Nessus)](https://www.tenable.com/cve/feeds?sort=newest) | 官方 CVE RSS，使用条目发布时间 | RSS 明示的 Severity |
| [AISLE（AI 发现）](https://aisle.com/cve-discoveries) | 近 90 天的公开 CVE，使用详情页发布日期 | 官方目录原始等级 |
| [Mozilla（AI 发现）](https://www.mozilla.org/en-US/security/advisories/) | 最近 6 份候选官方通告中，近 90 天披露且明确署名 AI 工具的 CVE | 单条漏洞的 impact |
| [Vulnerability-Wiki-PoC](https://github.com/SourByte05/Vulnerability-Wiki-PoC) | 近 90 天新增且仍存在的漏洞 Markdown 文档，使用新增提交的 UTC 时间 | 未提供，显示未知 |

本项目用于跟踪近期公开情报，**不是全量 CVE 镜像**，也包含没有 CVE 编号的漏洞文档。需要完整 CVE 数据集可使用 [CVE List V5](https://github.com/CVEProject/cvelistV5)。

### AI 发现的漏洞

“AI 发现”要求公开披露明确署名 AI 工具参与发现，不能仅因为漏洞发生在 AI 产品中或报告者来自 AI 公司就收录。

- **AISLE**：官方目录明确标注 AI 引擎发现，详情提供 CVE 和发布日期。首次采集最多 3 个并发读取详情，后续复用数据库已归档内容。
- **Mozilla**：读取[官方通告 YAML](https://github.com/mozilla/foundation-security-advisories)，匹配 reporter 中明确标注的 Claude、Mythos、Codex Security、Big Sleep 或 CodeMender；相同 CVE 跨 Firefox/Thunderbird 通告去重。

实现见 [ai_discoveries.py](src/crawler/ai_discoveries.py)，每条记录保存原文链接、日期和归因依据。

### Vulnerability-Wiki-PoC

实现见 [vulnerability_wiki.py](src/crawler/vulnerability_wiki.py)。通过 GitHub API 读取目录及提交记录，仅索引漏洞文档的标题和原文链接，不执行 PoC。

- 忽略图片、脚本、README 和普通内容修改。
- 按标题合并当前采集窗口内的跨月重复文档，保留较早的收录时间。
- 从标题提取 CVE；标题没有编号时保留为空。
- **收录时间不代表原始漏洞披露日期**，不会将月份目录伪装成精确披露日期。
- GitHub API 限流或请求失败会记录为来源失败，已有归档保留。

### 暂停采集的来源

以下为适配时的核验结果，停用原因保存在 [config/settings.yml](config/settings.yml) 的 crawler.disabled_sources 中：

| 来源 | 停用原因 |
| --- | --- |
| 360 | HTTPS 证书过期 |
| 红后 | 旧公开接口跳转到登录页面 |
| 斗象 | 旧站域名无法解析、数据接口 TLS 连接失败 |
| CNNVD | 旧页面返回 403，新接口要求签名校验 |
| 奇安信 | 旧 advisory 列表停更，最新记录为 2020-07-15 |

安全客和 CNVD 的旧采集实现也未启用。停用来源不发起采集、不在页面展示，数据库中的历史记录保留。来源恢复并完成适配后，删除相应停用配置，再运行 `--check` 验证。程序保留 HTTPS 证书校验。

## 页面与筛选

[GitHub Pages 看板](https://exp-tools.github.io/threat-broadcast/) 默认展示已启用来源近 90 天的有效归档，每页 25 条。

| 筛选项 | 规则 |
| --- | --- |
| 关键词 | 搜索 CVE 编号、漏洞标题和来源 |
| 漏洞来源 | 选择单个来源，或显示全部来源 |
| 漏洞等级 | 下拉选中后保持展开，可继续选择；再次点击取消，清空后显示全部等级 |
| 披露时间 | 全部、最近一天、最近一周、最近一月；分别对应展示窗口、过去 24 小时、7 天和 30 天 |

多个等级之间取并集，与来源、时间和关键词条件取交集。时间统一按 UTC 解析；Wiki 来源使用仓库收录时间。缺少原始等级的历史记录显示“未知”。

筛选覆盖展示窗口内的全部记录，不局限于每个来源 TOP30。禁用 JavaScript 时仍可查看各来源的前 N 条记录（由 `--top` 控制，默认 30）。CSS 和脚本链接带内容版本号，避免部署后旧缓存造成样式错位。

每次正常采集完成后都会重新生成页面，即使没有新增情报也会移除过期记录和来源。默认窗口由 crawler.max_age_days 配置；SQLite 历史记录不会因此删除。旧数据库会在初始化时自动增加等级列；重新采集可补充已有记录的等级，不重复入库，也不以未知等级覆盖已知等级。

## 本地运行

建议使用 **Python 3.11**（与 CI 一致）及独立虚拟环境。Git 用于拉取代码、提交和发布；Node.js 用于运行前端筛选测试。

```bash
git clone https://github.com/EXP-Tools/threat-broadcast.git
cd threat-broadcast
python -m venv .venv
```

Linux / macOS：

```bash
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py --check
.venv/bin/python main.py --no-notify
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --check
.\.venv\Scripts\python.exe main.py --no-notify
```

| 参数 | 用途 |
| --- | --- |
| `--check` | 联网检查所有启用来源，不写数据库或缓存、不生成页面、不发送通知；任一来源失败时退出码为 1 |
| `--no-notify` | 实际更新数据库、缓存和页面，不生成邮件缓存或发送通知 |
| `-t N` / `--top N` | 设置无 JavaScript 页面中每个来源的展示条数，不限制交互筛选的数据总量 |
| `-h` / `--help` | 查看全部参数 |

普通采集中，单个来源失败会记录异常并继续其他来源；全部启用来源失败时程序返回错误。空响应、解析失败和超过有效期的停更数据不会被当作成功。

本地预览（在项目根目录执行）：

```bash
python -m http.server 8765 --directory docs
```

浏览器打开 <http://localhost:8765/>。数据保存在 [data/cves.db](data/cves.db)，页面为 [docs/index.html](docs/index.html)。

## GitHub Actions 与 Pages 部署

工作流见 [autorun.yml](.github/workflows/autorun.yml)，使用 Python 3.11。

1. Fork 本仓库并启用 Actions。
2. 在仓库 **Settings → Secrets and variables → Actions** 中添加 `CRAWL_PWD`，值应与 [main.py](main.py) 的 `GIT_CRAWL_PWD` 一致，用于保留 Fork 启动保护。未配置时跳过自动采集。
3. 确保工作流拥有写入仓库内容的权限，以便提交生成的数据。
4. 在 **Settings → Pages** 中选择从 `master` 分支的 `/docs` 目录部署。
5. 在 Actions 手动运行采集工作流：默认 `check_only` 为 true，仅检查来源；取消勾选后才实际采集和提交。

定时任务为 `0 0/3 * * *`（UTC，每 3 小时），先验证，再采集，最后仅提交数据库、页面和来源缓存。PR 和涉及代码的 push 执行验证，不采集、不提交数据。GitHub 的定时任务可能延迟执行。

可选的 `GRAPHQL_TOKEN` 用于读取 Issue 收件人，兼容旧名称 `GRAPAQL_TOKEN`；未设置时工作流使用 `github.token`。若使用 Issue 收件人功能，应核对配置中的 github.owner / github.repo 指向自己的仓库。

### 通知状态

**当前 Actions 工作流没有实际邮件发送步骤，留下 Issue 邮箱不会自动获得邮件订阅。** 提供 GitHub Token 时，程序只生成邮件内容和收件人缓存；本地不提供 Token 时保留 SMTP 发送路径，需要自行配置发件账号和收件人。QQ 和 WeChat 推送函数目前为空实现。

只更新数据库和页面时使用 `--no-notify`。如需自行部署通知，可参考 [src/notice](src/notice) 和 [recv](recv)，并按自己的部署环境配置；不要把邮箱密码或 Token 提交到仓库。

服务器部署可用系统定时任务执行虚拟环境中的 `main.py --no-notify`，再提交 `data/cves.db`、`docs/index.html` 和来源缓存，推送到自己的 Pages 分支。程序每次正常采集都会重建页面。

## 验证

```bash
python -m pip check
python -m unittest discover -s tests -v
node --test tests/filters.test.cjs
python main.py --help
```

使用虚拟环境时，将上面的 python 替换为对应解释器路径。单元测试离线运行；真实来源可用 `--check` 单独检查。

## 目录

```text
threat-broadcast/
├── main.py                    # 运行入口
├── config/settings.yml        # 数据库、来源与通知配置
├── src/crawler/               # 情报来源适配器
├── src/dao/                   # SQLite 数据访问
├── src/notice/                # 页面及通知生成
├── data/cves.db               # 历史情报归档
├── cache/                     # 来源去重缓存
├── docs/                      # Pages 页面、样式和筛选脚本
├── tpl/                       # 页面与邮件模板
├── script/                    # 数据库初始化脚本
├── tests/                     # Python 与前端筛选测试
├── recv/                      # 本地收件人配置
└── .github/workflows/         # 自动验证与采集任务
```

## 版权与反馈

项目采用 [GPL-3.0](LICENSE) 许可证。原作者：[EXP](https://exp-blog.com)，邮箱：[289065406@qq.com](mailto:289065406@qq.com)。漏洞内容以原始来源为准，引用时请保留来源链接。问题和来源适配建议请提交至本仓库 [Issues](https://github.com/EXP-Tools/threat-broadcast/issues)。
