"""Kaplan-Meier completion curves with explicit risk sets and censoring.

Unsealed cases at the cutoff enter the risk set and are right-censored. The
median is reported as not reached when the curve never crosses 0.5; a mean of
the completed subsample is never substituted for it.
"""

from sealvault.codec import fail


def _curve(records):
    """records: list of (elapsed_seconds, is_event, case_id)."""
    records = sorted(records, key=lambda row: (row[0], not row[1], row[2]))
    times = []
    for elapsed, is_event, case_id in records:
        if not times or times[-1] != elapsed:
            times.append(elapsed)
    at_risk = len(records)
    survival = 1.0
    rows = []
    index = 0
    for elapsed in times:
        starts = at_risk
        events = 0
        censorings = 0
        members = []
        while index < len(records) and records[index][0] == elapsed:
            _, is_event, case_id = records[index]
            members.append(case_id)
            if is_event:
                events += 1
            else:
                censorings += 1
            index += 1
        if events:
            survival *= (at_risk - events) / at_risk
        rows.append({
            'time': elapsed,
            'risk_set': starts,
            'events': events,
            'censorings': censorings,
            'survival': round(survival, 6),
            'cumulative_completed': round(1.0 - survival, 6),
            'cases': sorted(members),
        })
        at_risk -= events + censorings
    return rows, survival


def _quantile(curve_rows, q):
    target = 1.0 - q
    for row in curve_rows:
        if row['events'] and row['survival'] <= target:
            return row['time'], True
    return None, False


def kaplan_meier(cases, elapsed):
    """Build the completion KM analysis.

    elapsed: callable(case) -> (seconds, is_completion_event).
    """
    records = []
    for case in cases:
        seconds, is_event = elapsed(case)
        records.append((seconds, is_event, case['case_id']))
    if not records:
        fail('km_empty', 'Kaplan-Meier requires a nonempty risk set')
    curve_rows, final_survival = _curve(records)
    quantiles = {}
    reached_flags = {}
    for label, fraction in (('q25', 0.25), ('median', 0.5), ('q75', 0.75)):
        value, reached = _quantile(curve_rows, fraction)
        quantiles[label] = value
        reached_flags[label] = reached
    events_total = sum(row['events'] for row in curve_rows)
    censored_total = sum(row['censorings'] for row in curve_rows)
    return {
        'risk_set': len(records),
        'events': events_total,
        'censored': censored_total,
        'median_reached': reached_flags['median'],
        'median': quantiles['median'],
        'quantiles': {
            'q25': quantiles['q25'],
            'median': quantiles['median'],
            'q75': quantiles['q75'],
        },
        'quantile_reached': {
            'q25': reached_flags['q25'],
            'median': reached_flags['median'],
            'q75': reached_flags['q75'],
        },
        'final_survival': round(final_survival, 6),
        'curve': curve_rows,
    }


def elapsed_natural(calendar, case):
    end = case['sealed_at'] or case['abandoned_at'] or case['cutoff']
    return calendar.natural_seconds(case['created_at'], end), case['sealed_at'] is not None


def elapsed_business(calendar, case):
    end = case['sealed_at'] or case['abandoned_at'] or case['cutoff']
    return calendar.business_seconds(case['created_at'], end), case['sealed_at'] is not None
