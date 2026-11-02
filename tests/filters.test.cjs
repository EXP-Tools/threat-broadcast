const { test } = require('node:test');
const assert = require('node:assert/strict');
const { timestamp, matches, filterRecords } = require('../docs/js/app.js');
const now = Date.parse('2026-11-02T12:00:00Z');
const records = [
  { id: 'CVE-2026-10001', title: 'SQL injection', source: 'AISLE', severity: 'CRITICAL', time: '2026-11-02 10:00:00' },
  { id: 'CVE-2026-10002', title: 'Memory safety', source: 'Mozilla', severity: 'HIGH', time: '2026-10-28' },
  { id: 'CVE-2026-10003', title: 'Old report', source: 'AISLE', severity: '', time: '2026-09-01' },
];
test('timestamps are interpreted as UTC for both dates and datetimes', () => {
  assert.equal(timestamp('2026-11-02 10:00:00'), Date.parse('2026-11-02T10:00:00Z'));
  assert.equal(timestamp('2026-10-28'), Date.parse('2026-10-28T00:00:00Z'));
});
test('day, week and month filters cover the complete record collection', () => {
  assert.deepEqual(filterRecords(records, { days: 1 }, now).map(r => r.id), ['CVE-2026-10001']);
  assert.equal(filterRecords(records, { days: 7 }, now).length, 2);
  assert.equal(filterRecords(records, { days: 30 }, now).length, 2);
  assert.equal(filterRecords(records, { days: 0 }, now).length, 3);
});
test('source, severity and keyword conditions combine', () => {
  assert.equal(filterRecords(records, { source: 'AISLE', severity: 'CRITICAL', days: 7, query: 'sql' }, now).length, 1);
  assert.equal(filterRecords(records, { source: 'Mozilla', severity: 'CRITICAL' }, now).length, 0);
  assert.equal(filterRecords(records, { severity: 'UNKNOWN' }, now).length, 1);
  assert.equal(filterRecords(records, { query: 'cve-2026-10002' }, now).length, 1);
});
test('time boundaries are inclusive and future or invalid dates do not match', () => {
  assert.equal(matches({ time: '2026-11-01 12:00:00' }, { days: 1 }, now), true);
  assert.equal(matches({ time: '2026-11-01 11:59:59' }, { days: 1 }, now), false);
  assert.equal(matches({ time: '2026-11-03 12:00:00' }, { days: 1 }, now), false);
  assert.equal(matches({ time: 'not a date' }, { days: 7 }, now), false);
});
