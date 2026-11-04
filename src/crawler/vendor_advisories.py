"""Official vendor disclosures with attributed, structured metadata."""

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from urllib.parse import parse_qs, urlsplit

import requests
from lxml import etree, html
from color_log.clog import log

import src.config as config
from src.bean.cve_info import CVEInfo
from src.crawler._base_crawler import BaseCrawler
from src.utils.severity import normalize, from_score


def utc(value):
    value = str(value or '').strip()
    value = re.sub(r'(\.)(\d+)(?=Z|[+-]\d{2}:?\d{2}$|$)',
                   lambda match: '.' + match[2][:6].ljust(6, '0'), value)
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        date = parsedate_to_datetime(value)
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def plain(value):
    value = unescape(str(value or ''))
    if '<' in value and '>' in value:
        value = html.fromstring('<div>' + value + '</div>').text_content()
    return ' '.join(value.split())


def cve_ids(value):
    return list(dict.fromkeys(re.findall(r'\bCVE-\d{4}-\d{4,}\b', value.upper())))


def score(value):
    try:
        number = float(value)
        return number if 0 <= number <= 10 else None
    except (TypeError, ValueError):
        return None


def section(doc, label):
    headings = doc.xpath('//*[self::h2 or self::h3][normalize-space(.)=$label]', label=label)
    values = []
    if headings:
        for element in headings[0].itersiblings():
            if element.tag in ('h2', 'h3'):
                break
            values.append(plain(element.text_content()))
    return '\n'.join(values)


class VendorSource(BaseCrawler):
    NAME = ''
    HOME = ''

    def NAME_CH(self):
        return self.NAME

    def NAME_EN(self):
        return self.NAME

    def HOME_PAGE(self):
        return self.HOME

    @property
    def limit(self):
        return max(1, min(int(config.settings.crawler.get('vendor_limit', 100)), 500))

    def recent(self, date):
        now = datetime.now(timezone.utc)
        stamp = datetime.fromisoformat(utc(date)).replace(tzinfo=timezone.utc)
        return now - timedelta(days=config.settings.crawler.get('max_age_days', 90) or 90) <= stamp <= now

    def request(self, url, **kwargs):
        response = requests.get(url, headers=self.headers(), timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response

    def record(self, identifier, title, url, published, **metadata):
        cve = CVEInfo()
        cve.src, cve.id, cve.title, cve.url = self.NAME, identifier, plain(title), url
        cve.time = utc(published)
        cve.metadata = {'publisher': self.NAME, 'published_at': cve.time, 'time_kind': 'published', **metadata}
        # Stable across edits to titles, summaries, scores and product lists.
        identity = '|'.join((self.NAME, metadata.get('advisory_id', url), identifier))
        cve.md5 = hashlib.md5(identity.encode('utf-8')).hexdigest()
        return cve

    def rss(self, url):
        doc = etree.fromstring(self.request(url).content,
                               parser=etree.XMLParser(resolve_entities=False, no_network=True))
        items = doc.findall('channel/item')
        if not items:
            raise ValueError('%s RSS 格式异常或为空' % self.NAME)
        return items

    def details(self, candidates, fetch):
        # A failed detail is logged; a valid RSS summary remains useful and is
        # explicitly marked summary-only instead of inventing missing metadata.
        with ThreadPoolExecutor(max_workers=3) as pool:
            batches = list(pool.map(fetch, candidates))
        records = [record for batch in batches for record in batch if self.recent(record.time)]
        records.sort(key=lambda cve: (cve.time, cve.id), reverse=True)
        return records[:self.limit]


class PaloAlto(VendorSource):
    NAME = 'Palo Alto Networks'
    HOME = 'https://security.paloaltonetworks.com/'

    def get_cves(self):
        data = self.request(self.HOME + 'json').json()
        if not isinstance(data, list):
            raise ValueError('Palo Alto JSON 格式异常')
        records = [self.parse(item) for item in data if item.get('date') and self.recent(item['date'])]
        return sorted(records, key=lambda cve: cve.time, reverse=True)[:self.limit]

    def parse(self, item):
        identifier = item['ID']
        versions = item.get('version', [])
        affected, fixed = item.get('affected', []), item.get('fixed', [])
        statuses = [{'product': version.strip(),
                     'affected': affected[i] if i < len(affected) else '',
                     'fixed': fixed[i] if i < len(fixed) else ''} for i, version in enumerate(versions)]
        cve = self.record(', '.join(cve_ids(identifier)), item['title'], self.HOME + identifier,
                          item['date'], advisory_id=identifier, updated_at=utc(item.get('updated') or item['date']),
                          affected_products=item.get('product', []), product_status=statuses,
                          cvss_score=score(item.get('baseScore')),
                          remediation='\n'.join(plain(x.get('value')) for x in item.get('solution', [])),
                          workaround='\n'.join(plain(x.get('value')) for x in item.get('work_around', [])))
        cve.severity = normalize(item.get('baseSeverity')) or from_score(item.get('baseScore'))
        cve.info = '\n'.join(plain(x.get('value')) for x in item.get('problem', []))
        return cve


class Fortinet(VendorSource):
    NAME = 'Fortinet'
    HOME = 'https://fortiguard.fortinet.com/psirt'
    FEED = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml'

    def get_cves(self):
        candidates = [item for item in self.rss(self.FEED) if self.recent(item.findtext('pubDate'))]
        return self.details(candidates[:self.limit], self.fetch_detail)

    def fetch_detail(self, item):
        url, date = item.findtext('link'), item.findtext('pubDate')
        summary = plain(item.findtext('description'))
        advisory = url.rstrip('/').split('/')[-1]
        cve = self.record(', '.join(cve_ids(summary)), item.findtext('title'), url, date,
                          advisory_id=advisory, collection_status='summary_only')
        cve.md5 = hashlib.md5((self.NAME + '|' + advisory).encode('utf-8')).hexdigest()
        cve.info = summary
        match = re.search(r'CVSSv3 Score:\s*([\d.]+)', summary)
        if match:
            cve.metadata['cvss_score'] = score(match[1])
            cve.metadata['cvss_version'] = '3'
            cve.severity = from_score(match[1])
        try:
            return [self.parse_detail(self.request(url).content, cve)]
        except Exception as exc:
            log.warn('[Fortinet] %s 详情失败，仅使用 RSS：%s' % (advisory, exc))
            return [cve]

    def parse_detail(self, content, cve):
        doc = html.fromstring(content)
        fields = {plain(row.xpath('string(./td[1])')): plain(row.xpath('string(./td[2])'))
                  for row in doc.xpath('//tr[td]')}
        if 'IR Number' not in fields or 'Published Date' not in fields:
            raise ValueError('Fortinet 详情结构异常')
        cve.time = datetime.strptime(fields['Published Date'], '%b %d, %Y').strftime('%Y-%m-%d 00:00:00')
        cve.metadata.update(published_at=cve.time, collection_status='detail',
                            updated_at=datetime.strptime(fields.get('Updated Date') or fields['Published Date'],
                                                         '%b %d, %Y').strftime('%Y-%m-%d 00:00:00'))
        cve.metadata['cvss_score'] = score(fields.get('CVSSv3 Score'))
        cve.metadata['cvss_version'] = '3'
        cve.metadata['known_exploited'] = {'Yes': True, 'No': False}.get(fields.get('Known Exploited'))
        cve.severity = normalize(fields.get('Severity')) or cve.severity
        # The detail's explicit CVE ID is authoritative; RSS prose can mention
        # other CVEs for comparison or in portfolio investigations.
        identifiers = cve_ids(fields.get('CVE ID', ''))
        if identifiers:
            cve.id = ', '.join(identifiers)
        statuses = []
        for table in doc.xpath('//table[.//th]'):
            headers = [plain(x.text_content()).lower() for x in table.xpath('.//th')]
            if not any('solution' in value or 'upgrade' in value for value in headers):
                continue
            for row in table.xpath('.//tr[td]'):
                cells = [plain(x.text_content()) for x in row.xpath('./td')]
                if cells:
                    statuses.append(dict(zip(headers, cells)))
        cve.metadata['product_status'] = statuses
        cve.metadata['affected_products'] = [item['version'] for item in statuses
            if item.get('version') and item.get('affected', '').lower() not in ('not affected', 'none', '')]
        vector_links = doc.xpath('//a[contains(@href,"vector=")]/@href')
        if vector_links:
            params = parse_qs(urlsplit(vector_links[0].strip()).query)
            cve.metadata['cvss_vector'] = next(iter(params.get('vector', [])), '')
            cve.metadata['cvss_version'] = next(iter(params.get('version', [])), '3')
        cve.metadata['remediation'] = section(doc, 'Solutions') or section(doc, 'Solution')
        cve.info = section(doc, 'Summary') or cve.info
        return cve


class Cisco(VendorSource):
    NAME = 'Cisco'
    HOME = 'https://sec.cloudapps.cisco.com/security/center/'
    FEED = HOME + 'psirtrss20/CiscoSecurityAdvisory.xml'

    def get_cves(self):
        candidates = [item for item in self.rss(self.FEED) if self.recent(item.findtext('pubDate'))]
        return self.details(candidates[:self.limit], self.fetch_detail)

    def fetch_detail(self, item):
        url = item.findtext('link').split('?')[0]
        advisory = url.rstrip('/').split('/')[-1]
        summary = plain(item.findtext('description'))
        fallback = self.record(', '.join(cve_ids(summary)), item.findtext('title'), url,
                               item.findtext('pubDate'), advisory_id=advisory,
                               time_kind='updated', collection_status='summary_only')
        fallback.metadata.pop('published_at')
        fallback.metadata['updated_at'] = fallback.time
        fallback.info = summary
        match = re.search(r'Security Impact Rating:\s*(Critical|High|Medium|Low)', summary, re.I)
        fallback.severity = normalize(match[1]) if match else ''
        if not fallback.id and not fallback.severity:
            # RSS also contains advance publication notices with no disclosed
            # vulnerability; those are not vulnerability records.
            return []
        try:
            data = self.request(url + '/csaf/' + advisory + '.json').json()
            return self.parse_csaf(data, url)
        except Exception as exc:
            log.warn('[Cisco] %s CSAF 失败，仅使用 RSS：%s' % (advisory, exc))
            return [fallback]

    def parse_csaf(self, data, url):
        document = data['document']
        tracking = document['tracking']
        if not data.get('vulnerabilities'):
            raise ValueError('Cisco CSAF 没有漏洞条目')
        products = {}

        def walk(node, parents=()):
            if not isinstance(node, dict):
                return
            names = parents + ((node['name'],) if node.get('name') else ())
            if 'product' in node:
                product = node['product']
                products[product['product_id']] = ' / '.join(names + (product['name'],))
            for branch in node.get('branches', []):
                walk(branch, names)
            for product in node.get('full_product_names', []):
                products[product['product_id']] = product['name']
        walk(data.get('product_tree', {}))
        records = []
        for vulnerability in data['vulnerabilities']:
            identifier = vulnerability.get('cve', '')
            if not identifier:
                continue
            metrics = [entry[key] for entry in vulnerability.get('scores', [])
                       for key in ('cvss_v4', 'cvss_v3', 'cvss_v2') if key in entry]
            metric = max(metrics, key=lambda x: (str(x.get('version', '')), score(x.get('baseScore')) or 0), default={})
            status = vulnerability.get('product_status', {})
            cve = self.record(identifier, vulnerability.get('title') or document['title'], url,
                              tracking['initial_release_date'], advisory_id=tracking['id'],
                              updated_at=utc(tracking['current_release_date']),
                              cvss_score=score(metric.get('baseScore')), cvss_vector=metric.get('vectorString', ''),
                              cvss_version=metric.get('version', ''),
                              affected_products=[products.get(key, key) for key in status.get('known_affected', [])],
                              fixed_products=[products.get(key, key) for key in status.get('fixed', [])],
                              remediation='\n'.join(x.get('details', '') for x in vulnerability.get('remediations', [])),
                              references=[x['url'] for x in vulnerability.get('remediations', []) if x.get('url')],
                              collection_status='detail')
            cve.severity = normalize(metric.get('baseSeverity')) or from_score(metric.get('baseScore'), metric.get('version', '3'))
            notes = document.get('notes', [])
            cve.info = '\n'.join(x['text'] for x in notes if x.get('category') == 'summary')
            fixed = [x['text'] for x in notes if x.get('title') == 'Fixed Software']
            if fixed:
                cve.metadata['remediation'] = '\n'.join(fixed)
            records.append(cve)
        if not records:
            raise ValueError('Cisco CSAF 没有公开 CVE')
        return records


class ZDI(VendorSource):
    NAME = 'ZDI'
    HOME = 'https://www.zerodayinitiative.com/'

    def get_cves(self):
        candidates = [item for item in self.rss(self.HOME + 'rss/published/')
                      if self.recent(item.findtext('pubDate'))]
        return self.details(candidates[:self.limit], self.fetch_detail)

    def fetch_detail(self, item):
        url = item.findtext('link').replace('http://', 'https://', 1)
        cve = self.record('', item.findtext('title'), url, item.findtext('pubDate'),
                          advisory_id=url.rstrip('/').split('/')[-1], collection_status='summary_only')
        cve.info = plain(item.findtext('description'))
        try:
            return [self.parse_detail(self.request(url).content, cve)]
        except Exception as exc:
            log.warn('[ZDI] %s 详情失败，仅使用 RSS：%s' % (url, exc))
            return [cve]

    def parse_detail(self, content, cve):
        doc = html.fromstring(content)
        fields = {}
        for row in doc.xpath('//div[contains(concat(" ",normalize-space(@class)," ")," metadata-row ")]'):
            label = row.xpath('string(.//p[contains(@class,"metadata-label")])').strip()
            values = [plain(x.text_content()) for x in row.xpath('.//*[contains(@class,"metadata-value")]')]
            fields[label] = values
        if 'CVSS Score' not in fields:
            raise ValueError('ZDI 详情结构异常')
        cve.id = ', '.join(cve_ids(' '.join(fields.get('CVE ID', []))))
        cve.metadata.update(collection_status='detail',
                            affected_products=fields.get('Affected Products', []),
                            vendors=fields.get('Affected Vendors', []),
                            cvss_score=score(next(iter(fields.get('CVSS Score', [])), None)),
                            remediation=section(doc, 'Additional Details'))
        vector_links = doc.xpath('//a[contains(@href,"calculator/")]/@href')
        if vector_links and '#' in vector_links[0]:
            vector = vector_links[0].split('#', 1)[1]
            cve.metadata['cvss_vector'] = vector
            cve.metadata['cvss_version'] = vector.split('/')[0].replace('CVSS:', '')
        cve.severity = from_score(cve.metadata.get('cvss_score'), version=cve.metadata.get('cvss_version', '3'))
        cve.info = section(doc, 'Vulnerability Details') or cve.info
        timeline = section(doc, 'Disclosure Timeline')
        updated = re.search(r'(\d{4}-\d{2}-\d{2})\s*-\s*Advisory Updated', timeline, re.I)
        if updated:
            cve.metadata['updated_at'] = utc(updated[1])
        return cve


class RedHat(VendorSource):
    NAME = 'Red Hat'
    HOME = 'https://access.redhat.com/'
    API = HOME + 'hydra/rest/securitydata/'

    def get_cves(self):
        after = datetime.now(timezone.utc) - timedelta(days=config.settings.crawler.get('max_age_days', 90) or 90)
        data = self.request(self.API + 'cve.json', params={
            'after': after.strftime('%Y-%m-%d'), 'per_page': self.limit, 'page': 1}).json()
        if not isinstance(data, list):
            raise ValueError('Red Hat CVE 列表格式异常')
        return self.details(data, self.fetch_detail)

    def fetch_detail(self, item):
        identifier = item['CVE']
        vector = item.get('cvss3_scoring_vector') or ''
        cve = self.record(identifier, item.get('bugzilla_description') or identifier,
                          self.HOME + 'security/cve/' + identifier, item['public_date'],
                          advisory_id=identifier, cvss_score=score(item.get('cvss3_score')),
                          cvss_vector=vector, cvss_version=vector.split('/')[0][5:] if vector.startswith('CVSS:') else '',
                          cwe=item.get('CWE') or '', collection_status='summary_only')
        cve.severity = normalize(item.get('severity'))
        try:
            data = self.request(self.API + 'cve/' + identifier + '.json').json()
            return [self.parse_detail(data, cve)]
        except Exception as exc:
            log.warn('[Red Hat] %s 详情失败，仅使用列表：%s' % (identifier, exc))
            return [cve]

    def parse_detail(self, data, cve):
        if data.get('name') != cve.id:
            raise ValueError('Red Hat 详情 CVE 不匹配')
        cve.info = '\n'.join(data.get('details', []))
        cve.metadata.update(collection_status='detail',
                            affected_products=list(dict.fromkeys(x['product_name'] for x in data.get('package_state', [])
                                if x.get('fix_state') in ('Affected', 'Fix deferred', 'Will not fix'))),
                            product_status=data.get('package_state', []),
                            fixes=data.get('affected_release', []),
                            remediation=plain(data.get('mitigation', {}).get('value', '')),
                            references=[url for value in data.get('references', []) for url in value.split()])
        return cve


class MSRC(VendorSource):
    NAME = 'Microsoft MSRC'
    HOME = 'https://msrc.microsoft.com/update-guide/'
    API = 'https://api.msrc.microsoft.com/cvrf/v3.0/'

    def headers(self):
        return {**super().headers(), 'Accept': 'application/json'}

    def get_cves(self):
        data = self.request(self.API + 'updates').json()
        releases = [item for item in data['value'] if self.recent(item['InitialReleaseDate'])]
        releases.sort(key=lambda x: x['InitialReleaseDate'], reverse=True)
        records = {}
        for release in releases:
            document = self.request(self.API + 'cvrf/' + release['ID']).json()
            for cve in self.parse_document(document, release['ID']):
                if self.recent(cve.time):
                    # A CVE can recur in a later month's product update.
                    existing = records.get(cve.id)
                    if existing is None:
                        records[cve.id] = cve
                    else:
                        published = min(existing.time, cve.time)
                        newest, other = (cve, existing) if cve.metadata['updated_at'] > existing.metadata['updated_at'] else (existing, cve)
                        newest.time = published
                        newest.metadata['published_at'] = published
                        for key in ('affected_products', 'fixes'):
                            combined = []
                            for value in newest.metadata.get(key, []) + other.metadata.get(key, []):
                                if value not in combined:
                                    combined.append(value)
                            newest.metadata[key] = combined
                        records[cve.id] = newest
        return sorted(records.values(), key=lambda x: (x.time, x.id), reverse=True)[:self.limit]

    def parse_document(self, data, release):
        products = {}
        def walk(node):
            if isinstance(node, dict):
                if 'ProductID' in node and 'Value' in node:
                    products[node['ProductID']] = node['Value']
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(data.get('ProductTree', {}))
        records = []
        for vulnerability in data['Vulnerability']:
            identifier = vulnerability['CVE']
            revisions = [x['Date'] for x in vulnerability.get('RevisionHistory', [])
                         if x.get('Date', '').startswith(('19', '20'))]
            # Do not label an old CVE with the current monthly document date.
            published = vulnerability.get('ReleaseDate', '') if vulnerability.get('ReleaseDateSpecified') else ''
            if not published.startswith(('19', '20')):
                published = min(revisions, default='')
            if not published:
                continue
            metric = max(vulnerability.get('CVSSScoreSets', []),
                         key=lambda x: score(x.get('BaseScore')) or 0, default={})
            affected = [products.get(key, key) for status in vulnerability.get('ProductStatuses', [])
                        if status.get('Type') == 3 for key in status.get('ProductID', [])]
            fixes = [{'description': plain(x.get('Description', {}).get('Value', '')),
                      'url': x.get('URL', ''), 'fixed_build': x.get('FixedBuild', ''),
                      'products': [products.get(key, key) for key in x.get('ProductID', [])]}
                     for x in vulnerability.get('Remediations', []) if x.get('Type') == 2]
            cve = self.record(identifier, vulnerability['Title']['Value'], self.HOME + 'vulnerability/' + identifier,
                              published, advisory_id=identifier, release=release,
                              date_basis='MSRC ReleaseDate' if vulnerability.get('ReleaseDateSpecified') else 'MSRC 最早修订日期',
                              updated_at=utc(max(revisions, default=published)),
                              cvss_score=score(metric.get('BaseScore')), cvss_vector=metric.get('Vector', ''),
                              affected_products=list(dict.fromkeys(affected)), fixes=fixes,
                              cwe=[x.get('ID') for x in vulnerability.get('CWE', []) if x.get('ID')])
            vector = metric.get('Vector', '')
            if vector.startswith('CVSS:'):
                cve.metadata['cvss_version'] = vector.split('/')[0][5:]
            severities = [normalize(x.get('Description', {}).get('Value')) for x in vulnerability.get('Threats', [])
                          if x.get('Type') == 3]
            cve.severity = next((x for x in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE') if x in severities), '')
            cve.severity = cve.severity or from_score(metric.get('BaseScore'))
            cve.info = '\n'.join(plain(x.get('Value')) for x in vulnerability.get('Notes', []) if x.get('Type') == 2)
            records.append(cve)
        return records
