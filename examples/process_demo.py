"""Local drill for process analytics over the custody-chain example.

The drill reuses examples.context.build() so the same synthetic records feed
both the existing custody workflow and the new process analysis. It only
handles process metadata: no evidence content is read or printed.
"""

import json

from examples.context import build, load
from sealvault.process.analytics import ProcessAnalytics

CUTOFF = '2026-11-10T00:00:00Z'
COHORT_AFTER = '2026-11-05T00:00:00Z'
COHORT_BEFORE = '2026-11-06T00:00:00Z'


def run(save=False):
    calendar = load()['calendar']
    vault, _ = build()
    try:
        desk = ProcessAnalytics(vault.db)
        envelope = desk.run(
            'drill-process-analysis', CUTOFF, calendar,
            COHORT_AFTER, COHORT_BEFORE)
        saved = desk.save(envelope) if save else None
        data = envelope['payload']['data']
        km = data['summary']['km']['natural']
        return {
            'ok': True,
            'calendar_version': data['calendar']['version'],
            'calendar_fingerprint': data['calendar_fingerprint'],
            'counts': data['counts'],
            'path_counts': data['summary']['path_counts'],
            'handoff_decisions': data['summary']['handoff_decisions'],
            'still_waiting': data['summary']['handoff_wait']['still_waiting'],
            'turnaround_completed': data['summary']['turnaround']['completed']['natural'],
            'km': {
                'risk_set': km['risk_set'],
                'events': km['events'],
                'censored': km['censored'],
                'median_reached': km['median_reached'],
                'median': km['median'],
            },
            'diagnostics': data['diagnostics'],
            'saved': saved,
        }
    finally:
        vault.close()


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, sort_keys=True))
