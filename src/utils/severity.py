"""Canonical severity values; absent or unrecognized ratings remain unknown."""


LABELS = {'CRITICAL': '严重', 'HIGH': '高危', 'MEDIUM': '中危',
          'LOW': '低危', 'NONE': '无危害', '': '未知'}


def normalize(value):
    aliases = {'MODERATE': 'MEDIUM', 'IMPORTANT': 'HIGH',
               '严重': 'CRITICAL', '高危': 'HIGH', '中危': 'MEDIUM', '低危': 'LOW'}
    value = str(value or '').strip().upper()
    value = aliases.get(value, value)
    return value if value in LABELS else ''


def from_score(score, version='3'):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return ''
    if not 0 <= score <= 10:
        return ''
    if score == 0:
        return 'NONE'
    if score >= 9 and not str(version).startswith('2'):
        return 'CRITICAL'
    if score >= 7:
        return 'HIGH'
    return 'MEDIUM' if score >= 4 else 'LOW'


def from_nvd(metrics):
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        records = sorted(metrics.get(key, []), key=lambda record: record.get('type') != 'Primary')
        for record in records:
            cvss = record.get('cvssData', {})
            value = normalize(cvss.get('baseSeverity') or record.get('baseSeverity'))
            value = value or from_score(cvss.get('baseScore'), cvss.get('version', '3'))
            if value:
                return value
    return ''
