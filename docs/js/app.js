(function () {
  'use strict';
  const labels = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', NONE: '无危害', UNKNOWN: '未知' };
  const levels = Object.keys(labels);
  const pageSize = 25;

  function timestamp(value) {
    let text = String(value || '').trim().replace(' ', 'T');
    if (/^\d{4}-\d{2}-\d{2}$/.test(text)) text += 'T00:00:00Z';
    else if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(text)) text += 'Z';
    return Date.parse(text);
  }

  function matches(record, filters, now = Date.now()) {
    const severity = record.severity || 'UNKNOWN';
    if (filters.source && record.source !== filters.source) return false;
    const selected = filters.severity ? [].concat(filters.severity) : [];
    if (selected.length && !selected.includes(severity)) return false;
    if (Number(filters.days)) {
      const time = timestamp(record.time);
      if (!Number.isFinite(time) || time > now || time < now - Number(filters.days) * 86400000) return false;
    }
    const query = String(filters.query || '').trim().toLocaleLowerCase();
    const meta = record.metadata || {};
    return !query || [record.id, record.title, record.source, meta.advisory_id,
      ...(meta.affected_products || []), ...(meta.vendors || []), ...(meta.cwe ? [].concat(meta.cwe) : [])]
      .join(' ').toLocaleLowerCase().includes(query);
  }

  function filterRecords(records, filters, now = Date.now()) {
    return records.filter(record => matches(record, filters, now))
      .sort((a, b) => (timestamp(b.time) || 0) - (timestamp(a.time) || 0));
  }

  function relatedRecords(records) {
    const index = new Map();
    records.forEach(record => {
      const ids = [...new Set(String(record.id || '').toUpperCase().match(/\bCVE-\d{4}-\d{4,}\b/g) || [])];
      ids.forEach(id => { if (!index.has(id)) index.set(id, []); index.get(id).push(record); });
    });
    return record => {
      const ids = String(record.id || '').toUpperCase().match(/\bCVE-\d{4}-\d{4,}\b/g) || [];
      return [...new Set(ids.flatMap(id => index.get(id) || []))].filter(other => other !== record && other.source !== record.source);
    };
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { timestamp, matches, filterRecords, relatedRecords };
  if (typeof document === 'undefined') return;

  function init() {
    const records = JSON.parse(document.getElementById('intelligence-data').textContent);
    const related = relatedRecords(records);
    const byId = id => document.getElementById(id);
    const search = byId('search'), source = byId('source-filter'), severity = byId('severity-filter');
    const timeButtons = Array.from(document.querySelectorAll('[data-days]'));
    const tbody = byId('vulnerability-rows');
    const state = { days: 0, page: 1, severities: [] };
    const severityOptions = Array.from(document.querySelectorAll('[data-severity]'));
    const severityPopup = byId('severity-popup');
    function openSeverity(open, focusOption = false) {
      severityPopup.hidden = !open;
      severity.setAttribute('aria-expanded', String(open));
      if (open && focusOption) (severityOptions.find(option => state.severities.includes(option.dataset.severity)) || severityOptions[0]).focus();
    }
    const create = (tag, className, text) => {
      const element = document.createElement(tag);
      if (className) element.className = className;
      if (text !== undefined) element.textContent = text;
      return element;
    };
    const counts = Object.fromEntries(levels.map(level => [level, 0]));
    records.forEach(record => { counts[record.severity || 'UNKNOWN'] += 1; });
    const distribution = byId('severity-distribution');
    levels.forEach(level => {
      if (!counts[level]) return;
      const segment = create('span', 'distribution-' + level.toLowerCase());
      segment.style.flexGrow = String(counts[level]);
      segment.title = `${labels[level]} ${counts[level]} 条`;
      distribution.append(segment);
    });
    distribution.setAttribute('aria-label', levels.map(level => `${labels[level]} ${counts[level]} 条`).join('，'));

    function row(record) {
      const tr = create('tr');
      const id = create('td', 'cve-id', record.id || '未编号');
      const title = create('td', 'vuln-title');
      const titleText = create('div', 'title-text', record.title);
      titleText.title = record.title;
      title.append(titleText);
      const meta = record.metadata || {};
      const others = related(record);
      if (Object.keys(meta).length || others.length) {
        const details = create('details', 'intel-details');
        const sourceCount = new Set(others.map(other => other.source)).size;
        details.append(create('summary', '', '情报详情' + (sourceCount ? ` · 另 ${sourceCount} 个来源` : '')));
        const list = create('dl', 'intel-metadata');
        const field = (label, value) => {
          if (value === undefined || value === null || value === '' || (Array.isArray(value) && !value.length)) return;
          const names = { product: '产品', product_name: '产品', products: '产品', package_name: '软件包',
            package: '修复包', affected: '受影响版本', fixed: '修复版本', fixed_build: '修复构建',
            fix_state: '修复状态', description: '说明', advisory: '修复通告', url: '链接', cpe: 'CPE', impact: '影响等级',
            version: '产品版本', solution: '修复建议' };
          const readable = item => item && typeof item === 'object' ? Object.entries(item)
            .filter(([, v]) => v !== '' && v !== null && v !== undefined)
            .map(([key, v]) => `${names[key] || key}：${Array.isArray(v) ? v.join('、') : v}`).join(' · ') : String(item);
          const text = Array.isArray(value) ? value.map(readable).join('\n') : String(value);
          list.append(create('dt', '', label), create('dd', '', text));
        };
        field('发布方', meta.publisher);
        field('通告编号', meta.advisory_id);
        field('受影响厂商', meta.vendors);
        const cvssVersion = meta.cvss_version || (String(meta.cvss_vector || '').match(/^CVSS:([\d.]+)/) || [])[1];
        field('CVSS', meta.cvss_score === undefined || meta.cvss_score === null ? '' : `${meta.cvss_score}${cvssVersion ? ' / v' + cvssVersion : ''}`);
        field('评分向量', meta.cvss_vector);
        field('首次披露（UTC）', meta.published_at);
        field('更新（UTC）', meta.updated_at);
        field('仓库收录（UTC）', meta.collected_at);
        field('时间依据', ({ published: '首次披露', updated: '通告更新', collected: '仓库收录' })[meta.time_kind]);
        field('日期来源', meta.date_basis);
        field('受影响产品', meta.affected_products);
        field('产品状态', meta.product_status);
        field('已修复产品', meta.fixed_products);
        field('修复记录', meta.fixes);
        field('修复建议', meta.remediation);
        field('缓解措施', meta.workaround);
        field('CWE', meta.cwe);
        field('已知在野利用', typeof meta.known_exploited === 'boolean' ? (meta.known_exploited ? '来源明确标注：是' : '来源明确标注：否') : '');
        if (meta.collection_status === 'summary_only') field('采集说明', '详情暂不可用，当前仅收录官方列表或 RSS 摘要');
        details.append(list);
        if (meta.references && meta.references.length) {
          const references = create('ul', 'related-records');
          meta.references.filter(url => /^https?:\/\//i.test(url)).forEach(url => {
            const item = create('li');
            const link = create('a', '', url);
            link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer';
            item.append(link); references.append(item);
          });
          if (references.children.length) {
            details.append(create('p', 'related-heading', '参考链接'), references);
          }
        }
        if (others.length) {
          details.append(create('p', 'related-heading', '相同 CVE 的其他来源（当前展示窗口内）'));
          const links = create('ul', 'related-records');
          const seen = new Set();
          others.forEach(other => {
            const key = other.source + other.url;
            if (seen.has(key) || !/^https?:\/\//i.test(other.url)) return;
            seen.add(key);
            const item = create('li');
            const link = create('a', '', `${other.source} · ${other.id} · ${labels[other.severity || 'UNKNOWN']}`);
            link.href = other.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
            item.append(link); links.append(item);
          });
          details.append(links);
        }
        title.append(details);
      }
      const grade = record.severity || 'UNKNOWN';
      const severityCell = create('td');
      severityCell.append(create('span', 'severity severity-' + grade.toLowerCase(), labels[grade] || labels.UNKNOWN));
      const sourceCell = create('td');
      sourceCell.append(create('span', 'source-name', record.source));
      const time = create('td', 'disclosed-at', record.time.slice(0, 10));
      time.title = record.time + ' UTC';
      if (meta.time_kind === 'updated') time.title += '（通告更新时间）';
      if (meta.time_kind === 'collected') time.title += '（仓库收录时间）';
      const linkCell = create('td');
      if (/^https?:\/\//i.test(record.url)) {
        const link = create('a', 'detail-link', '查看 ↗');
        link.href = record.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.setAttribute('aria-label', `查看 ${record.id || record.title} 的原始披露`);
        linkCell.append(link);
      }
      tr.append(id, title, severityCell, sourceCell, time, linkCell);
      return tr;
    }

    function render() {
      const filtered = filterRecords(records, { source: source.value, severity: state.severities, days: state.days, query: search.value });
      const selection = byId('severity-selection');
      selection.replaceChildren();
      const selectedLevels = levels.filter(level => state.severities.includes(level));
      if (!selectedLevels.length) selection.textContent = '全部等级';
      selectedLevels.forEach(level => selection.append(create('span', 'selected-grade', labels[level])));
      severityOptions.forEach(option => option.setAttribute('aria-selected', String(state.severities.includes(option.dataset.severity))));
      const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
      state.page = Math.max(1, Math.min(state.page, pages));
      const start = (state.page - 1) * pageSize;
      const fragment = document.createDocumentFragment();
      filtered.slice(start, start + pageSize).forEach(record => fragment.append(row(record)));
      tbody.replaceChildren(fragment);
      byId('vulnerability-table').hidden = filtered.length === 0;
      byId('empty-state').hidden = filtered.length !== 0;
      byId('result-summary').textContent = `命中 ${filtered.length.toLocaleString('zh-CN')} 条 / 共 ${records.length.toLocaleString('zh-CN')} 条`;
      byId('page-summary').textContent = filtered.length ? `显示 ${start + 1}–${Math.min(start + pageSize, filtered.length)} 条 · 每页 ${pageSize} 条` : '无匹配记录';
      byId('page-number').textContent = `${state.page} / ${pages}`;
      byId('previous-page').disabled = state.page === 1;
      byId('next-page').disabled = state.page === pages;
      timeButtons.forEach(button => button.setAttribute('aria-pressed', String(Number(button.dataset.days) === state.days)));
    }

    function changed() { state.page = 1; render(); }
    function reset() { search.value = ''; source.value = ''; state.severities = []; state.days = 0; openSeverity(false); changed(); }
    search.addEventListener('input', changed);
    source.addEventListener('change', changed);
    severity.addEventListener('click', () => openSeverity(severityPopup.hidden));
    severity.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); openSeverity(true, true); }
    });
    severityOptions.forEach((option, index) => {
      option.addEventListener('click', () => {
        const value = option.dataset.severity;
        state.severities = state.severities.includes(value) ? state.severities.filter(level => level !== value) : [...state.severities, value];
        changed();
      });
      option.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
          event.preventDefault();
          severityOptions[(index + (event.key === 'ArrowDown' ? 1 : -1) + severityOptions.length) % severityOptions.length].focus();
        } else if (event.key === 'Home' || event.key === 'End') {
          event.preventDefault(); severityOptions[event.key === 'Home' ? 0 : severityOptions.length - 1].focus();
        }
      });
    });
    byId('clear-severity').addEventListener('click', () => { state.severities = []; changed(); });
    document.addEventListener('click', event => { if (!byId('severity-multiselect').contains(event.target)) openSeverity(false); });
    byId('severity-multiselect').addEventListener('keydown', event => {
      if (event.key === 'Escape') { event.preventDefault(); openSeverity(false); severity.focus(); }
      if (event.key === 'Tab') openSeverity(false);
    });
    timeButtons.forEach(button => button.addEventListener('click', () => { state.days = Number(button.dataset.days); changed(); }));
    byId('reset-filters').addEventListener('click', reset);
    byId('empty-reset').addEventListener('click', reset);
    byId('previous-page').addEventListener('click', () => { state.page -= 1; render(); });
    byId('next-page').addEventListener('click', () => { state.page += 1; render(); });
    render();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
