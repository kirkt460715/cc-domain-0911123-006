"""Process analysis orchestration, privacy boundary and immutable snapshots."""

from sealvault.codec import (canonical, digest, envelope, fail, key, loads,
                             timestamp, unwrap)
from sealvault.process import events as events_module
from sealvault.process.calendar import BusinessCalendar
from sealvault.process.flow import aggregate, build_flow
from sealvault.process.roles import build_role_stats
from sealvault.process.stats import summarize
from sealvault.process.survival import (elapsed_business, elapsed_natural,
                                        kaplan_meier)

DDL = '''
CREATE TABLE IF NOT EXISTS process_analyses(analysis_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,cutoff TEXT NOT NULL,calendar_version TEXT NOT NULL,head_digest TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);
'''

ANALYSIS_FORMAT = 'sealvault-process-analysis'


class ProcessAnalytics:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('analysis_transaction', 'Initialize process analytics outside transactions')
        database.connection.executescript(DDL)

    def run(self, analysis_id, cutoff, calendar_config, create_after, create_before, heads=None):
        key(analysis_id)
        cutoff = timestamp(cutoff)
        create_after = timestamp(create_after)
        create_before = timestamp(create_before)
        if create_before <= create_after:
            fail('cohort_window', 'Cohort window requires create_after < create_before')
        calendar = BusinessCalendar.from_config(calendar_config)
        rows = self.db.all(
            'SELECT case_id,created_at FROM cases WHERE created_at>=? AND created_at<? ORDER BY created_at,case_id',
            (create_after, create_before))
        cohort = [row['case_id'] for row in rows]
        pinned = heads if heads is not None else {}
        if not isinstance(pinned, dict):
            fail('analysis_heads', 'heads must map case identifiers to chain head hashes')
        unknown = sorted(set(pinned) - set(cohort))
        if unknown:
            fail('analysis_heads', 'Pinned head references a case outside the cohort', cases=unknown)
        missing = sorted(set(cohort) - set(pinned))
        if pinned and missing:
            fail('analysis_heads', 'Pinned heads must fix every cohort case', cases=missing)

        cases = []
        diagnostics = []
        for case_id in cohort:
            current_head = self.db.scalar(
                'SELECT entry_hash FROM custody WHERE case_id=? ORDER BY sequence DESC LIMIT 1', (case_id,))
            pinned_head = pinned.get(case_id, current_head)
            case = events_module.extract_case(self.db, case_id, cutoff, pinned_head)
            cases.append(case)
            for problem in case['diagnostics']:
                diagnostics.append(problem)

        valid_cases = [case for case in cases if case['valid']]
        flows = []
        for case in valid_cases:
            flow = build_flow(case, calendar)
            flows.append({'case_id': case['case_id'], 'case': case, 'flow': flow})

        summary = aggregate(flows)
        summary['handoff_wait'] = _wait_summary(flows, summary['waiting'])
        summary['turnaround'] = _turnaround_summary(flows)
        if valid_cases:
            km_natural = kaplan_meier(valid_cases, lambda item: elapsed_natural(calendar, item))
            km_business = kaplan_meier(valid_cases, lambda item: elapsed_business(calendar, item))
            by_role = []
            for role in sorted({case['creator_role'] or 'unknown' for case in valid_cases}):
                members = [case for case in valid_cases
                           if (case['creator_role'] or 'unknown') == role]
                by_role.append({'role': role,
                                'km': kaplan_meier(
                                    members,
                                    lambda item, cal=calendar: elapsed_natural(cal, item))})
            summary['km'] = {'natural': km_natural, 'business': km_business,
                             'by_creator_role': by_role}
        else:
            summary['km'] = None
        role_stats = build_role_stats(flows, calendar) if flows else {'roles': [], 'ownership_partition': []}

        head_digest = digest({case['case_id']: case['head'] for case in cases})
        snapshot = {
            'analysis_id': analysis_id,
            'saved_at': self.db.clock(),
            'cohort': {
                'criterion': 'first_creation',
                'create_after': create_after,
                'create_before': create_before,
                'cohort_start': rows[0]['created_at'] if rows else None,
                'cohort_end': rows[-1]['created_at'] if rows else None,
            },
            'cutoff': cutoff,
            'calendar': calendar.config(),
            'calendar_fingerprint': calendar.fingerprint(),
            'head_digest': head_digest,
            'heads': [{'case_id': case['case_id'], 'pinned': case['pinned_head'],
                       'head': case['head']} for case in cases],
            'counts': {
                'cohort': len(cases),
                'included': len(valid_cases),
                'excluded': len(cases) - len(valid_cases),
                'seals': sum(1 for case in valid_cases if case['sealed_at']),
                'censored': sum(1 for case in valid_cases if not case['sealed_at']),
            },
            'cases': [_case_view(case, next((item['flow'] for item in flows
                                             if item['case_id'] == case['case_id']), None))
                      for case in cases],
            'summary': summary,
            'roles': role_stats,
            'diagnostics': diagnostics,
        }
        enforce_privacy(snapshot)
        return envelope(ANALYSIS_FORMAT, snapshot)

    def save(self, analysis):
        data = unwrap(analysis, ANALYSIS_FORMAT)
        enforce_privacy(data)
        analysis_id = key(data['analysis_id'])
        body = canonical(data)
        checksum = digest(data)
        with self.db.transaction():
            prior = self.db.one('SELECT digest FROM process_analyses WHERE analysis_id=?', (analysis_id,))
            if prior is not None:
                if prior['digest'] != checksum:
                    fail('analysis_exists', 'A different immutable analysis already uses this identifier')
                return {'duplicate': True, 'analysis_id': analysis_id, 'digest': checksum}
            self.db.execute(
                'INSERT INTO process_analyses VALUES(?,?,?,?,?,?,?)',
                (analysis_id, data['saved_at'], data['cutoff'], data['calendar']['version'],
                 data['head_digest'], body, checksum))
            self.db.log('process.analysis_saved', {'analysis_id': analysis_id, 'digest': checksum})
        return {'duplicate': False, 'analysis_id': analysis_id, 'digest': checksum}

    def get(self, analysis_id):
        key(analysis_id)
        row = self.db.one('SELECT body,digest FROM process_analyses WHERE analysis_id=?', (analysis_id,))
        if row is None:
            fail('analysis_missing', 'Saved process analysis does not exist')
        data = loads(row['body'])
        if digest(data) != row['digest']:
            fail('analysis_corrupt', 'Saved process analysis checksum differs')
        return envelope(ANALYSIS_FORMAT, data)


def _case_view(case, flow):
    view = {
        'case_id': case['case_id'],
        'valid': case['valid'],
        'creator_actor': case['creator_actor'],
        'creator_role': case['creator_role'],
        'created_at': case['created_at'],
        'state': case['state'],
        'sealed_at': case['sealed_at'],
        'abandoned_at': case['abandoned_at'],
        'cutoff': case['cutoff'],
        'head': case['head'],
        'pinned': case['pinned_head'],
        'entry_count': case['entry_count'],
        'activities': [dict(activity) for activity in case['activities']],
        'diagnostics': case['diagnostics'],
    }
    if flow is not None:
        view['path'] = flow['path']
        view['segments'] = flow['segments']
        view['owner_intervals'] = flow['owner_intervals']
        view['turnaround'] = flow['turnaround']
    return view


def _wait_summary(flows, waiting_rows):
    natural, business = [], []
    open_natural, open_business = [], []
    for item in flows:
        for segment in item['flow']['segments']:
            if segment['stage'] != 'handoff_wait':
                continue
            natural.append(segment['natural_seconds'])
            business.append(segment['business_seconds'])
            if segment['open']:
                open_natural.append(segment['natural_seconds'])
                open_business.append(segment['business_seconds'])
    return {
        'all': {'natural': summarize(natural), 'business': summarize(business)},
        'still_waiting': {'natural': summarize(open_natural),
                          'business': summarize(open_business),
                          'records': waiting_rows},
    }


def _turnaround_summary(flows):
    def collect(predicate):
        natural, business = [], []
        records = []
        for item in flows:
            turnaround = item['flow']['turnaround']
            if not predicate(turnaround):
                continue
            natural.append(turnaround['natural_seconds'])
            business.append(turnaround['business_seconds'])
            records.append({
                'case_id': turnaround['case_id'],
                'completed': turnaround['completed'],
                'censored': turnaround['censored'],
                'start_at': turnaround['start_at'],
                'ended_at': turnaround['ended_at'],
                'natural_seconds': turnaround['natural_seconds'],
                'business_seconds': turnaround['business_seconds'],
            })
        return {'natural': summarize(natural), 'business': summarize(business), 'records': records}
    return {
        'all': collect(lambda row: True),
        'completed': collect(lambda row: row['completed']),
        'censored': collect(lambda row: row['censored']),
    }


def enforce_privacy(value, trail='snapshot'):
    """Reject any key outside the process-metadata whitelist and any bytes."""
    if isinstance(value, dict):
        for name, item in value.items():
            if not isinstance(name, str) or name not in events_module.ALLOWED_KEYS:
                fail('analysis_privacy', 'Analysis envelope contains a non-whitelisted field',
                     field=name, path=trail)
            if name in events_module.FORBIDDEN_KEYS:
                fail('analysis_privacy', 'Analysis envelope contains evidence metadata',
                     field=name, path=trail)
            enforce_privacy(item, trail + '.' + name)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            enforce_privacy(item, f'{trail}[{index}]')
    elif isinstance(value, (str, int, float, bool)) or value is None:
        return
    else:
        fail('analysis_privacy', 'Analysis envelope contains an unsupported value type',
             path=trail, type=type(value).__name__)
