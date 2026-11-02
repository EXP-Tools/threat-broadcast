import importlib
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
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
    main_module = importlib.import_module('main')

from src.bean.cve_info import CVEInfo
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao


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
        self.bean.time = '2026-11-01'
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
            dao.return_value.insert.return_value = True
            self.assertEqual(self.crawler.cves(), [self.cve])
            dao.return_value.insert.assert_called_once()
            self.crawler.to_cache.assert_called_once_with(self.cve)

    def test_connection_closes_after_cache_failure(self):
        self.crawler.to_cache.side_effect = OSError('disk full')
        with patch.object(crawler_module, 'SqliteDBC') as db, \
                patch.object(crawler_module, 'TCvesDao'):
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


class SourceTests(unittest.TestCase):
    def record(self, identifier, published):
        return {'id': identifier, 'published': published,
                'descriptions': [{'lang': 'en', 'value': 'Test vulnerability'}]}

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
        <description><![CDATA[<h3>Description</h3><p>Test vulnerability</p>]]></description>
        </item></channel></rss>'''
        with patch.object(tenable_module.requests, 'get') as get:
            get.return_value.status_code = 200
            get.return_value.content = rss
            cves = tenable_module.Tenable().get_cves()
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0].time, '2026-11-01 10:00:00')
            self.assertEqual(cves[0].title, 'Test vulnerability')

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
        source.cves.return_value = [Mock()]
        with patch.object(main_module, 'get_sources', return_value=[source]), \
                patch.object(main_module.page, 'to_page') as page_write, \
                patch.object(main_module.mail, 'to_mail') as mail, \
                patch.object(main_module.qq, 'to_group') as qq, \
                patch.object(main_module.wechat, 'to_wechat') as wechat:
            main_module.main(10, False, '', '', '', '', '', '', notify=False)
            source.cves.assert_called_once()
            page_write.assert_called_once_with(10)
            mail.assert_not_called()
            qq.assert_not_called()
            wechat.assert_not_called()

    def test_database_paths_are_resolved_from_project_directory(self):
        actual_config = importlib.import_module('src.config')
        self.assertEqual(Path(actual_config.settings.database['dbpath']),
                         Path(config.PRJ_DIR, 'data/cves.db'))
        self.assertEqual(Path(actual_config.settings.database['sqlpath']),
                         Path(config.PRJ_DIR, 'script/cves-create.sql'))


if __name__ == '__main__':
    unittest.main()
