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
    return !query || [record.id, record.title, record.source].join(' ').toLocaleLowerCase().includes(query);
  }

  function filterRecords(records, filters, now = Date.now()) {
    return records.filter(record => matches(record, filters, now))
      .sort((a, b) => (timestamp(b.time) || 0) - (timestamp(a.time) || 0));
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { timestamp, matches, filterRecords };
  if (typeof document === 'undefined') return;

  function init() {
    const records = JSON.parse(document.getElementById('intelligence-data').textContent);
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
      const grade = record.severity || 'UNKNOWN';
      const severityCell = create('td');
      severityCell.append(create('span', 'severity severity-' + grade.toLowerCase(), labels[grade] || labels.UNKNOWN));
      const sourceCell = create('td');
      sourceCell.append(create('span', 'source-name', record.source));
      const time = create('td', 'disclosed-at', record.time.slice(0, 10));
      time.title = record.time + ' UTC';
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
