<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="公开漏洞情报与 AI 发现的漏洞归档，按来源、漏洞等级和披露时间筛选。">
  <title>Threat Broadcast · 漏洞情报</title>
  <link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%%3E%%3Crect width='64' height='64' rx='12' fill='%%23101820'/%%3E%%3Ctext x='12' y='44' fill='%%2369b7c0' font-family='monospace' font-size='38'%%3E!%%3C/text%%3E%%3C/svg%%3E">
  <link rel="stylesheet" href="css/intelligence.css?v=%(css_version)s">
  <script defer src="js/app.js?v=%(js_version)s"></script>
</head>
<body>
  <a class="skip-link" href="#intelligence">跳到漏洞列表</a>
  <header class="topbar">
    <a class="wordmark" href="./"><span class="brand-mark" aria-hidden="true">[!]</span> THREAT BROADCAST <span class="brand-cn">威胁情报播报</span></a>
    <a class="repo-link" href="https://github.com/EXP-Tools/threat-broadcast" target="_blank" rel="noopener noreferrer">GitHub 仓库 <span aria-hidden="true">↗</span></a>
  </header>
  <main id="intelligence" class="workspace">
    <section class="masthead" aria-labelledby="page-title">
      <div><p class="eyebrow">公开披露 / Vulnerability intelligence</p><h1 id="page-title">漏洞情报<span class="title-dot">.</span></h1><p class="intro">跟踪公开漏洞与 AI 发现的安全缺陷，快速定位需要关注的风险。</p></div>
      <div class="snapshot"><span class="status-dot" aria-hidden="true"></span>归档快照<time datetime="%(generated_iso)s">%(datetime)s UTC</time><span>最近 %(window_days)s 天 · 仅展示活跃来源</span></div>
    </section>
    <section class="overview" aria-label="情报概览">
      <div><span class="metric-label">归档漏洞</span><strong id="total-count">%(total_count)s</strong><span class="metric-note">近 %(window_days)s 天归档</span></div>
      <div><span class="metric-label">严重 / 高危</span><strong id="high-count">%(high_count)s</strong><span class="metric-note">优先核查暴露资产</span></div>
      <div><span class="metric-label">活跃来源</span><strong id="source-count">%(source_count)s</strong><span class="metric-note">含 AI 发现的漏洞</span></div>
      <div class="signal"><span class="metric-label">等级分布</span><div id="severity-distribution" class="distribution" aria-label="漏洞等级分布"></div><span id="distribution-caption" class="metric-note">等级依据各来源公开披露，缺失时标记为未知。</span></div>
    </section>
    <section class="filter-panel" aria-label="筛选漏洞">
      <div class="filter-top"><h2>情报检索 <span class="section-code">/ FILTER</span></h2><button type="button" id="reset-filters" class="text-button">重置筛选</button></div>
      <div class="filter-grid">
        <label class="search-field"><span>关键词</span><input id="search" type="search" placeholder="搜索 CVE 编号、产品或漏洞描述" autocomplete="off"></label>
        <label><span>漏洞来源</span><select id="source-filter"><option value="">全部来源</option>%(source_options)s</select></label>
        <div class="filter-field multiselect" id="severity-multiselect">
          <span id="severity-label">漏洞等级</span>
          <button type="button" id="severity-filter" class="multiselect-trigger" aria-haspopup="listbox" aria-expanded="false" aria-controls="severity-options" aria-labelledby="severity-label severity-selection"><span id="severity-selection">全部等级</span><span aria-hidden="true">⌄</span></button>
          <div id="severity-popup" class="multiselect-popup" hidden>
            <div id="severity-options" role="listbox" aria-labelledby="severity-label" aria-multiselectable="true">
              <button type="button" role="option" data-severity="CRITICAL" aria-selected="false" tabindex="-1">严重<span aria-hidden="true">✓</span></button>
              <button type="button" role="option" data-severity="HIGH" aria-selected="false" tabindex="-1">高危<span aria-hidden="true">✓</span></button>
              <button type="button" role="option" data-severity="MEDIUM" aria-selected="false" tabindex="-1">中危<span aria-hidden="true">✓</span></button>
              <button type="button" role="option" data-severity="LOW" aria-selected="false" tabindex="-1">低危<span aria-hidden="true">✓</span></button>
              <button type="button" role="option" data-severity="NONE" aria-selected="false" tabindex="-1">无危害<span aria-hidden="true">✓</span></button>
              <button type="button" role="option" data-severity="UNKNOWN" aria-selected="false" tabindex="-1">未知<span aria-hidden="true">✓</span></button>
            </div>
            <div class="multiselect-footer"><span>可继续选择，再次点击取消</span><button type="button" id="clear-severity">清空</button></div>
          </div>
        </div>
      </div>
      <div class="time-filter"><span>披露时间</span><div role="group" aria-label="披露时间范围"><button type="button" data-days="0" aria-pressed="true">全部</button><button type="button" data-days="1" aria-pressed="false">最近一天</button><button type="button" data-days="7" aria-pressed="false">最近一周</button><button type="button" data-days="30" aria-pressed="false">最近一月</button></div><span class="time-hint">按披露时间计算，最近一月为 30 天</span></div>
    </section>
    <section class="results" aria-labelledby="results-heading">
      <div class="results-heading"><h2 id="results-heading">漏洞列表 <span class="section-code">/ INTELLIGENCE FEED</span></h2><p id="result-summary" role="status" aria-live="polite">共 %(total_count)s 条记录</p></div>
      <div class="table-scroll" tabindex="0" role="region" aria-label="漏洞列表，窄屏可横向滚动">%(table)s</div>
      <div id="empty-state" class="empty-state" hidden><span class="empty-symbol" aria-hidden="true">∅</span><h3>没有符合条件的漏洞</h3><p>尝试扩大时间范围、切换来源，或清除关键词。</p><button type="button" id="empty-reset">重置筛选</button></div>
      <nav class="pagination" aria-label="漏洞列表分页"><span id="page-summary">当前展示各来源的前 %(top_limit)s 条记录</span><div><button type="button" id="previous-page" disabled>上一页</button><span id="page-number">1</span><button type="button" id="next-page" disabled>下一页</button></div></nav>
      <noscript><p class="notice">启用 JavaScript 后可筛选全部近期归档记录并分页；当前展示各来源前 %(top_limit)s 条。</p></noscript>
    </section>
    <aside class="source-notice">%(source_status)s</aside>
    <footer><span>Threat Broadcast · 公开漏洞情报归档</span><span>等级来自原始披露，未知不代表低风险。请结合资产版本核查。</span></footer>
  </main>
  <script type="application/json" id="intelligence-data">%(records_json)s</script>
</body>
</html>
