import importlib
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, patch


# Keep these unit tests offline; replace only configuration and external adapters.
config = types.ModuleType('src.config')
config.PRJ_DIR = str(Path(__file__).resolve().parents[1])
config.CHARSET = 'utf-8'
config.settings = types.SimpleNamespace(
    database={}, crawler={'max_age_days': 0},
    github={'owner': 'test', 'repo': 'test', 'graphql': 'https://example.com/graphql'})
logger = types.ModuleType('color_log.clog')
logger.log = Mock(spec=['info', 'warn', 'error'])
sqlite_adapter = types.ModuleType('pypdm.dbc._sqlite')
sqlite_adapter.SqliteDBC = Mock()
with patch.dict(sys.modules, {
    'src.config': config,
    'color_log.clog': logger,
    'pypdm.dbc._sqlite': sqlite_adapter,
}):
    crawler_module = importlib.import_module('src.crawler._base_crawler')
    page = importlib.import_module('src.notice.page')
    nvd_module = importlib.import_module('src.crawler.nvd')
    nsfocus_module = importlib.import_module('src.crawler.nsfocus')
    tenable_module = importlib.import_module('src.crawler.tenable')
    ai_module = importlib.import_module('src.crawler.ai_discoveries')
    main_module = importlib.import_module('main')

from src.bean.cve_info import CVEInfo
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao
from src.utils.severity import normalize, from_score, from_nvd


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.addCleanup(self.conn.close)
        schema = Path(config.PRJ_DIR, 'script/cves-create.sql').read_text()
        self.conn.executescript(schema)
        self.dao = TCvesDao()
        self.bean = TCves()
        self.bean.md5 = 'sample'
        self.bean.src = "Vendor's feed"
        self.bean.title = 'Test vulnerability'
        self.bean.time = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        self.assertTrue(self.dao.insert(self.conn, self.bean))

    def test_query_some_with_and_without_filters(self):
        self.assertEqual(len(self.dao.query_all(self.conn)), 1)
        rows = self.dao.query_some(self.conn, {'s_src =': self.bean.src})
        self.assertEqual([row.title for row in rows], [self.bean.title])

    def test_query_one(self):
        row = self.dao.query_one(self.conn, {'s_md5 =': 'sample'})
        self.assertIsNotNone(row)
        self.assertEqual(row.src, self.bean.src)

    def test_delete(self):
        self.assertTrue(self.dao.delete(self.conn, {'s_md5 =': 'sample'}))
        self.assertEqual(self.dao.count(self.conn), 0)

    def test_truncate(self):
        self.assertTrue(self.dao.truncate(self.conn))
        self.assertEqual(self.dao.count(self.conn), 0)

    def test_page_query_handles_quoted_source(self):
        rows = page.query_cves(self.conn, self.bean.src, 1)
        self.assertEqual([row.title for row in rows], [self.bean.title])
        self.assertEqual(page.query_cves(self.conn, "' OR 1=1 --", 1), [])

    def test_page_skips_empty_query_results(self):
        with patch.object(page, 'SqliteDBC'), \
                patch.object(page, 'query_srcs', return_value=['source']), \
                patch.object(page, 'query_cves', return_value=[]), \
                patch.object(page, 'create_html') as write:
            page.to_page(0)
            write.assert_called_once()

    def test_page_shows_disabled_source_reasons_as_text(self):
        with patch.dict(config.settings.crawler, {'disabled_sources': {'test': '<login required>'}}):
            status = page.format_source_status()
            self.assertIn('暂停更新', status)
            self.assertIn('&lt;login required&gt;', status)
            self.assertNotIn('<login required>', status)

    def test_page_escapes_vulnerability_text_and_links(self):
        self.conn.execute("update t_cves set s_title = ?, s_url = ?",
                          ('<script>alert(1)</script>', 'https://example.com/?q="test"'))
        with patch.object(page, 'SqliteDBC') as db, \
                patch.object(page, 'create_html') as write:
            db.return_value.conn.return_value = self.conn
            page.to_page(10)
            output = write.call_args.args[0]
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', output)
            self.assertIn('q=&quot;test&quot;', output)
            self.assertNotIn('<script>alert(1)</script>', output)

    def test_stale_and_invalid_sources_are_hidden_without_deleting_history(self):
        old = TCves()
        old.src, old.time, old.md5 = 'retired', '2000-01-01', 'old'
        self.assertTrue(self.dao.insert(self.conn, old))
        old.src, old.time, old.md5 = 'invalid', 'yt', 'invalid'
        self.assertTrue(self.dao.insert(self.conn, old))
        with patch.dict(config.settings.crawler, {'max_age_days': 90}):
            self.assertEqual(page.query_srcs(self.conn), [self.bean.src])
        self.assertEqual(self.dao.count(self.conn), 3)

    def test_disabled_source_is_hidden_even_when_its_archive_is_recent(self):
        self.assertEqual(page.query_srcs(self.conn, ['other active source']), [])
        self.assertEqual(page.query_srcs(self.conn, []), [])

    def test_severity_migration_is_idempotent_and_preserves_existing_rows(self):
        self.conn.execute('drop table t_cves')
        self.conn.execute('create table t_cves(s_md5 text, s_src text)')
        self.conn.execute("insert into t_cves values ('old', 'source')")
        self.conn.commit()
        TCvesDao.ensure_schema(self.conn)
        TCvesDao.ensure_schema(self.conn)
        self.assertEqual(self.conn.execute('select * from t_cves').fetchall(), [('old', 'source', '')])

    def test_existing_severity_is_updated_without_inserting_duplicate_or_erasing_known_grade(self):
        cve = CVEInfo()
        cve.md5, cve.src, cve.severity = 'sample', self.bean.src, 'HIGH'
        self.dao.set_severity(self.conn, cve)
        cve.severity = ''
        self.dao.set_severity(self.conn, cve)
        self.assertEqual(self.dao.count(self.conn), 1)
        self.assertEqual(self.dao.query_one(self.conn, {'s_md5 =': 'sample'}).severity, 'HIGH')

    def test_severity_column_renders_label_and_color_class(self):
        self.conn.execute("update t_cves set s_severity = 'CRITICAL'")
        with patch.object(page, 'SqliteDBC') as db, patch.object(page, 'create_html') as write:
            db.return_value.conn.return_value = self.conn
            page.to_page(10)
            output = write.call_args.args[0]
            self.assertIn('漏洞等级', output)
            self.assertIn('severity-critical', output)
            self.assertIn('严重', output)

    def test_dashboard_payload_contains_records_beyond_initial_top_limit(self):
        import json
        from lxml import html
        self.bean.md5 = 'second'
        self.bean.title = '</script><script>alert(1)</script>'
        self.assertTrue(self.dao.insert(self.conn, self.bean))
        with patch.object(page, 'SqliteDBC') as db, patch.object(page, 'create_html') as write:
            db.return_value.conn.return_value = self.conn
            page.to_page(1)
            output = write.call_args.args[0]
            doc = html.fromstring(output)
            records = json.loads(doc.xpath('string(//script[@id="intelligence-data"])'))
            self.assertEqual(len(records), 2)
            self.assertEqual(len(doc.xpath('//tbody[@id="vulnerability-rows"]/tr')), 1)
            self.assertTrue(any(record['title'] == self.bean.title for record in records))
            self.assertNotIn('</script><script>alert(1)</script>', output)


class CrawlerTests(unittest.TestCase):
    def setUp(self):
        self.crawler = crawler_module.BaseCrawler()
        self.crawler.NAME_CH = lambda: 'test'
        self.cve = CVEInfo()
        self.cve.title = 'Test vulnerability'
        self.crawler.get_cves = Mock(return_value=[self.cve, self.cve])
        self.crawler.load_cache = Mock(return_value=set())
        self.crawler.to_cache = Mock()

    def test_failed_insert_is_not_cached_or_announced(self):
        with patch.object(crawler_module, 'SqliteDBC') as db, \
                patch.object(crawler_module, 'TCvesDao') as dao:
            dao.return_value.query_one.return_value = None
            dao.return_value.insert.return_value = False
            self.assertEqual(self.crawler.cves(), [])
            self.crawler.to_cache.assert_not_called()
            db.return_value.close.assert_called_once()
            self.assertEqual(self.crawler.last_error, '数据库写入失败')

    def test_fetch_failure_is_reported_without_opening_database(self):
        self.crawler.get_cves.side_effect = ValueError('login page returned')
        with patch.object(crawler_module, 'SqliteDBC') as db:
            self.assertEqual(self.crawler.cves(), [])
            self.assertIn('ValueError: login page returned', self.crawler.last_error)
            db.assert_not_called()
            self.crawler.to_cache.assert_not_called()

    def test_stale_feed_is_rejected(self):
        self.cve.time = '2000-01-01'
        with patch.dict(config.settings.crawler, {'max_age_days': 90}):
            with self.assertRaisesRegex(ValueError, '2000-01-01'):
                self.crawler.fetch_cves()

    def test_empty_response_is_not_reported_as_healthy(self):
        self.crawler.get_cves.return_value = []
        with self.assertRaisesRegex(ValueError, '未获取到有效情报'):
            self.crawler.fetch_cves()

    def test_duplicates_in_one_response_are_stored_once(self):
        with patch.object(crawler_module, 'SqliteDBC'), \
                patch.object(crawler_module, 'TCvesDao') as dao:
            dao.return_value.query_one.return_value = None
            dao.return_value.insert.return_value = True
            self.assertEqual(self.crawler.cves(), [self.cve])
            dao.return_value.insert.assert_called_once()
            self.crawler.to_cache.assert_called_once_with(self.cve)

    def test_connection_closes_after_cache_failure(self):
        self.crawler.to_cache.side_effect = OSError('disk full')
        with patch.object(crawler_module, 'SqliteDBC') as db, \
                patch.object(crawler_module, 'TCvesDao') as dao:
            dao.return_value.query_one.return_value = None
            with self.assertRaises(OSError):
                self.crawler.cves()
            db.return_value.close.assert_called_once()

    def test_cache_retains_last_100_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory, 'test.dat')
            cache.write_text('\n'.join(str(i) for i in range(350)) + '\n')
            self.crawler.CACHE_PATH = lambda: str(cache)
            result = crawler_module.BaseCrawler.load_cache(self.crawler)
            self.assertEqual(result, {str(i) for i in range(250, 350)})
            self.assertEqual(len(cache.read_text().splitlines()), 100)

    def test_persisted_record_is_not_inserted_again_when_cache_expires(self):
        with patch.object(crawler_module, 'SqliteDBC'), \
                patch.object(crawler_module, 'TCvesDao') as dao:
            dao.return_value.query_one.return_value = TCves()
            self.assertEqual(self.crawler.cves(), [])
            dao.return_value.insert.assert_not_called()

    def test_cached_record_still_receives_updated_severity(self):
        self.cve.severity = 'HIGH'
        self.crawler.load_cache.return_value = {self.cve.MD5()}
        with patch.object(crawler_module, 'SqliteDBC'), patch.object(crawler_module, 'TCvesDao') as dao:
            self.assertEqual(self.crawler.cves(), [])
            self.assertEqual(dao.return_value.set_severity.call_count, 2)
            dao.return_value.insert.assert_not_called()


class AIDiscoveryTests(unittest.TestCase):
    def test_aisle_catalog_extracts_only_cves_in_recent_months(self):
        month = datetime.now(timezone.utc).strftime('%B %Y')
        content = '''<section data-wall-section><header><h2>%s</h2></header>
        <li data-cve data-product="Example"><a href="/cve-discoveries/cve-2026-12345">
        <p>Overflow &amp; read</p></a></li>
        <li data-cve><a href="https://unrelated.example.com/"><p>Other</p></a></li>
        </section><section data-wall-section><header><h2>January 2000</h2></header>
        <li data-cve><a href="/cve-discoveries/cve-2000-12345"><p>Old</p></a></li></section>''' % month
        records = ai_module.AISLE().parse_catalog(content)
        self.assertEqual(records, [('CVE-2026-12345', 'Example: Overflow & read',
                                   'https://aisle.com/cve-discoveries/cve-2026-12345', '')])

    def test_aisle_detail_uses_disclosure_date_and_requires_ai_attribution(self):
        import json
        data = {'@type': 'TechArticle', 'headline': 'CVE-2026-12345 — Discovered by AISLE',
                'datePublished': '2026-10-03T08:51:53Z', 'description': 'Description'}
        content = '<script type="application/ld+json">%s</script>' % json.dumps(data)
        cve = ai_module.AISLE().parse_detail(content, 'CVE-2026-12345', 'Title', 'https://aisle.com/test')
        self.assertEqual(cve.time, '2026-10-03 08:51:53')
        self.assertIn('AISLE', cve.info)
        with self.assertRaises(ValueError):
            ai_module.AISLE().parse_detail(content, 'CVE-2026-99999', 'Title', 'https://aisle.com/test')

    def test_aisle_catalog_changes_raise_instead_of_silent_empty_success(self):
        with self.assertRaises(ValueError):
            ai_module.AISLE().parse_catalog('<html>Login required</html>')

    def test_aisle_reuses_archive_without_requesting_known_detail_pages(self):
        source = ai_module.AISLE()
        url = 'https://aisle.com/cve-discoveries/cve-2026-12345'
        cve = CVEInfo()
        cve.time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with patch.object(ai_module.requests, 'get') as get, \
                patch.object(source, 'parse_catalog', return_value=[('CVE-2026-12345', 'Title', url, 'HIGH')]), \
                patch.object(source, 'load_archived', return_value={url: cve}):
            self.assertEqual(source.get_cves(), [cve])
            get.assert_called_once()

    def test_mozilla_requires_explicit_ai_agent_credit(self):
        data = {'announced': 'October 27, 2026', 'fixed_in': ['Firefox 159'], 'advisories': {
            'CVE-2026-12345': {'title': 'AI discovered bug', 'reporter': 'OpenAI Codex Security (kylebot)', 'impact': 'high'},
            'CVE-2026-12346': {'title': 'Human discovery', 'reporter': 'Researcher of OpenAI'},
            'CVE-2026-12347': {'title': 'Bug in AI library', 'reporter': 'Independent researcher'},
            'CVE-2026-12348': {'title': 'Claude finding', 'reporter': ['Researcher', 'Claude Opus 4.6']},
        }}
        cves = ai_module.MozillaAI().parse_advisory(data, 'mfsa2026-120')
        self.assertEqual([c.id for c in cves], ['CVE-2026-12345', 'CVE-2026-12348'])
        self.assertEqual(cves[0].time, '2026-10-27')
        self.assertEqual(cves[0].severity, 'HIGH')
        self.assertEqual(cves[0].url,
                         'https://www.mozilla.org/en-US/security/advisories/mfsa2026-120/#CVE-2026-12345')

    def test_mozilla_invalid_advisory_is_reported(self):
        with self.assertRaises(ValueError):
            ai_module.MozillaAI().parse_advisory({'login': True}, 'mfsa2026-120')

    def test_mozilla_sorts_advisory_numbers_and_deduplicates_shared_cves(self):
        import yaml
        data = {'announced': datetime.now(timezone.utc).strftime('%B %d, %Y'),
                'fixed_in': ['Firefox'], 'advisories': {
                    'CVE-2026-12345': {'title': 'Title', 'reporter': 'Claude Opus 4.6'}}}
        directory = Mock()
        year = datetime.now(timezone.utc).year
        directory.json.return_value = [{'name': 'mfsa%s-%s.yml' % (year, number)}
                                       for number in (9, 121, 122)]
        document = Mock(content=yaml.safe_dump(data).encode())
        with patch.object(ai_module.requests, 'get', side_effect=[directory, document, document, document]) as get:
            records = ai_module.MozillaAI().get_cves()
            self.assertEqual(len(records), 1)
            self.assertIn('mfsa%s-122' % year, records[0].url)
            self.assertIn('mfsa%s-122.yml' % year, get.call_args_list[1].args[0])

    def test_aisle_reads_archived_details_without_changing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'test.db')
            conn = sqlite3.connect(path)
            try:
                conn.executescript(Path(config.PRJ_DIR, 'script/cves-create.sql').read_text())
                bean = TCves()
                bean.src, bean.md5, bean.cves = 'AISLE（AI 发现）', 'test', 'CVE-2026-12345'
                bean.title, bean.time, bean.info, bean.url = 'Title', '2026-10-03', 'AI attribution', 'https://aisle.com/test'
                self.assertTrue(TCvesDao().insert(conn, bean))
            finally:
                conn.close()
            before = path.read_bytes()
            with patch.dict(config.settings.database, {'dbpath': str(path)}):
                known = ai_module.AISLE().load_archived()
            self.assertEqual(known[bean.url].id, bean.cves)
            self.assertEqual(path.read_bytes(), before)


class SourceTests(unittest.TestCase):
    def record(self, identifier, published):
        return {'id': identifier, 'published': published,
                'descriptions': [{'lang': 'en', 'value': 'Test vulnerability'}]}

    def test_cvss_mapping_and_unknown_values(self):
        self.assertEqual([from_score(s) for s in (0, 0.1, 4, 7, 9, 10)],
                         ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'CRITICAL'])
        self.assertEqual(from_score(9.8, '2.0'), 'HIGH')
        for value in (None, 'not rated', -1, 11, float('nan')):
            self.assertEqual(from_score(value), '')
        self.assertEqual(normalize('moderate'), 'MEDIUM')
        self.assertEqual(normalize('<script>'), '')

    def test_nvd_prefers_primary_metrics_and_preserves_unknown(self):
        metrics = {'cvssMetricV31': [
            {'type': 'Secondary', 'cvssData': {'baseSeverity': 'MEDIUM'}},
            {'type': 'Primary', 'cvssData': {'baseScore': 9.8, 'version': '3.1'}},
        ]}
        self.assertEqual(from_nvd(metrics), 'CRITICAL')
        self.assertEqual(from_nvd({}), '')

    def test_nvd_fetches_latest_page_instead_of_oldest(self):
        source = nvd_module.NVD()
        records = [self.record('CVE-2026-10000', '2026-11-01T01:00:00.000'),
                   self.record('CVE-2026-10001', '2026-11-01T02:00:00.000')]
        with patch.object(source, 'query', side_effect=[
            {'totalResults': 100, 'vulnerabilities': []},
            {'totalResults': 100, 'vulnerabilities': [{'cve': r} for r in records]},
        ]) as query, patch.object(nvd_module.time, 'sleep') as sleep:
            cves = source.get_cves(2)
            self.assertEqual(query.call_args.args[0]['startIndex'], 98)
            self.assertEqual([c.id for c in cves], ['CVE-2026-10001', 'CVE-2026-10000'])
            self.assertEqual(cves[0].time, '2026-11-01 02:00:00.000')
            self.assertEqual(cves[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2026-10001')
            sleep.assert_called_once_with(6)

    def test_nvd_small_page_does_not_request_again(self):
        source = nvd_module.NVD()
        record = self.record('CVE-2026-10000', '2026-11-01T01:00:00Z')
        with patch.object(source, 'query', return_value={
            'totalResults': 1, 'vulnerabilities': [{'cve': record}],
        }) as query:
            self.assertEqual(len(source.get_cves()), 1)
            query.assert_called_once()

    def test_nvd_http_error_is_not_reported_as_empty_data(self):
        with patch.object(nvd_module.requests, 'get') as get:
            get.return_value.raise_for_status.side_effect = RuntimeError('HTTP 403')
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                nvd_module.NVD().get_cves()

    def test_nvd_retries_transient_service_errors(self):
        unavailable = Mock(status_code=503)
        healthy = Mock(status_code=200)
        healthy.json.return_value = {'totalResults': 0, 'vulnerabilities': []}
        with patch.object(nvd_module.requests, 'get', side_effect=[unavailable, healthy]) as get, \
                patch.object(nvd_module.time, 'sleep') as sleep:
            self.assertEqual(nvd_module.NVD().query({})['totalResults'], 0)
            self.assertEqual(get.call_count, 2)
            sleep.assert_called_once_with(6)

    def test_nvd_retry_attempts_are_bounded(self):
        unavailable = Mock(status_code=503)
        unavailable.raise_for_status.side_effect = RuntimeError('HTTP 503')
        with patch.object(nvd_module.requests, 'get', return_value=unavailable) as get, \
                patch.object(nvd_module.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 503'):
                nvd_module.NVD().query({})
            self.assertEqual(get.call_count, 3)

    def test_nsfocus_parses_new_api_and_preserves_source_date(self):
        with patch.object(nsfocus_module.requests, 'get') as get:
            get.return_value.json.return_value = {'results': [{
                'bug_id': '218625', 'bug_name': 'Example路径遍历漏洞（CVE-2026-117510）',
                'update_time': '2026-10-28',
            }]}
            cves = nsfocus_module.Nsfocus().get_cves()
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0].time, '2026-10-28')
            self.assertEqual(cves[0].id, 'CVE-2026-117510')
            self.assertEqual(cves[0].title, 'Example路径遍历漏洞')
            self.assertEqual(cves[0].url, 'https://www.nsfocus.net/vulndb/218625')

    def test_nsfocus_schema_change_is_reported(self):
        with patch.object(nsfocus_module.requests, 'get') as get:
            get.return_value.json.return_value = {'login': True}
            with self.assertRaises(ValueError):
                nsfocus_module.Nsfocus().get_cves()

    def test_tenable_accepts_rss_without_xml_declaration(self):
        rss = b'''<rss><channel><item><title>CVE-2026-10000</title>
        <link>https://www.tenable.com/cve/CVE-2026-10000</link>
        <pubDate>Sun, 01 Nov 2026 10:00:00 +0000</pubDate>
        <description><![CDATA[<p>Critical Severity</p><h3>Description</h3><p>Test vulnerability</p>]]></description>
        </item></channel></rss>'''
        with patch.object(tenable_module.requests, 'get') as get:
            get.return_value.status_code = 200
            get.return_value.content = rss
            cves = tenable_module.Tenable().get_cves()
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0].time, '2026-11-01 10:00:00')
            self.assertEqual(cves[0].title, 'Test vulnerability')
            self.assertEqual(cves[0].severity, 'CRITICAL')

    def test_tenable_http_failure_is_not_hidden(self):
        with patch.object(tenable_module.requests, 'get') as get:
            get.return_value.raise_for_status.side_effect = RuntimeError('HTTP 403')
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                tenable_module.Tenable().get_cves()

    def test_disabled_sources_are_skipped(self):
        with patch.dict(config.settings.crawler, {'disabled_sources': {'NVD': 'maintenance'}}):
            self.assertNotIn('NVD', [src.NAME_EN() for src in main_module.get_sources()])

    def test_check_sources_reports_failure(self):
        source = Mock()
        source.NAME_CH.return_value = 'test'
        source.fetch_cves.side_effect = ValueError('bad response')
        with patch.object(main_module, 'get_sources', return_value=[source]):
            self.assertEqual(main_module.check_sources(), 1)

    def test_check_sources_does_not_write_data_or_send_notifications(self):
        source = Mock()
        source.fetch_cves.return_value = []
        with patch.object(main_module, 'get_sources', return_value=[source]), \
                patch.object(main_module, 'init') as init, \
                patch.object(main_module.mail, 'to_mail') as send:
            self.assertEqual(main_module.check_sources(), 0)
            source.cves.assert_not_called()
            init.assert_not_called()
            send.assert_not_called()

    def test_all_failed_sources_raise_instead_of_silent_success(self):
        source = Mock(last_error='HTTP 403')
        source.NAME_CH.return_value = 'test'
        source.cves.return_value = []
        with patch.object(main_module, 'get_sources', return_value=[source]):
            with self.assertRaisesRegex(RuntimeError, '所有已启用'):
                main_module.main(10, False, '', '', '', '', '', '')

    def test_database_initialization_failure_stops_execution(self):
        with patch.dict(config.settings.database, {'sqlpath': 'schema.sql'}), \
                patch.object(main_module, 'SqliteDBC') as db:
            db.return_value.exec_script.return_value = False
            with self.assertRaisesRegex(RuntimeError, '数据库初始化失败'):
                main_module.init()

    def test_no_notify_still_generates_page_without_sending_or_caching_notifications(self):
        source = Mock(last_error=None)
        source.NAME_CH.return_value = 'test'
        source.cves.return_value = [Mock()]
        with patch.object(main_module, 'get_sources', return_value=[source]), \
                patch.object(main_module.page, 'to_page') as page_write, \
                patch.object(main_module.mail, 'to_mail') as mail, \
                patch.object(main_module.qq, 'to_group') as qq, \
                patch.object(main_module.wechat, 'to_wechat') as wechat:
            main_module.main(10, False, '', '', '', '', '', '', notify=False)
            source.cves.assert_called_once()
            page_write.assert_called_once_with(10, active_sources=['test'])
            mail.assert_not_called()
            qq.assert_not_called()
            wechat.assert_not_called()

    def test_page_is_rebuilt_without_new_vulnerabilities(self):
        source = Mock(last_error=None)
        source.NAME_CH.return_value = 'test'
        source.cves.return_value = []
        with patch.object(main_module, 'get_sources', return_value=[source]), \
                patch.object(main_module.page, 'to_page') as page_write, \
                patch.object(main_module.mail, 'to_mail') as mail:
            main_module.main(10, False, '', '', '', '', '', '')
            page_write.assert_called_once_with(10, active_sources=['test'])
            mail.assert_not_called()

    def test_database_paths_are_resolved_from_project_directory(self):
        actual_config = importlib.import_module('src.config')
        self.assertEqual(Path(actual_config.settings.database['dbpath']),
                         Path(config.PRJ_DIR, 'data/cves.db'))
        self.assertEqual(Path(actual_config.settings.database['sqlpath']),
                         Path(config.PRJ_DIR, 'script/cves-create.sql'))


if __name__ == '__main__':
    unittest.main()
