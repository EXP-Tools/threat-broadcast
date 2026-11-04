const { test } = require('node:test');
const assert = require('node:assert/strict');
const { timestamp, matches, filterRecords, relatedRecords } = require('../docs/js/app.js');
const now = Date.parse('2026-11-02T12:00:00Z');
const records = [
  { id: 'CVE-2026-10001', title: 'SQL injection', source: 'AISLE', severity: 'CRITICAL', time: '2026-11-02 10:00:00' },
  { id: 'CVE-2026-10002', title: 'Memory safety', source: 'Mozilla', severity: 'HIGH', time: '2026-10-28' },
  { id: 'CVE-2026-10003', title: 'Old report', source: 'AISLE', severity: '', time: '2026-09-01' },
];
test('metadata products and advisory IDs are searchable', () => {
  const record = { metadata: { affected_products: ['PAN-OS'], advisory_id: 'FG-IR-26-001' } };
  assert.equal(matches(record, { query: 'pan-os' }), true);
  assert.equal(matches(record, { query: 'fg-ir-26-001' }), true);
});
test('cross-source CVE links exclude same-source records and unnumbered advisories', () => {
  const data = [{ id: 'CVE-2026-12345', source: 'A' }, { id: 'CVE-2026-12345, CVE-2026-12346', source: 'B' },
    { id: 'CVE-2026-12345', source: 'A' }, { id: '', source: 'C' }];
  const related = relatedRecords(data);
  assert.deepEqual(related(data[0]), [data[1]]);
  assert.deepEqual(related(data[3]), []);
});
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
test('multiple severity choices use OR and combine with other filters using AND', () => {
  assert.equal(filterRecords(records, { severity: ['CRITICAL', 'HIGH'] }, now).length, 2);
  assert.equal(filterRecords(records, { severity: ['CRITICAL', 'HIGH'], source: 'AISLE', days: 7 }, now).length, 1);
  assert.equal(filterRecords(records, { severity: ['HIGH', 'UNKNOWN'] }, now).length, 2);
  assert.equal(filterRecords(records, { severity: [] }, now).length, 3);
  assert.equal(filterRecords(records, { severity: ['LOW', 'MEDIUM'] }, now).length, 0);
});
