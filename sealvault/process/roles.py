"""Role attribution based on the actual holder of each time interval.

Owner intervals partition a case without overlap, so the same case is never
counted to every role for its full lifetime. Handoff waiting is assigned to the
destination role that has to act on the proposal.
"""

from sealvault.process.flow import WAIT, WORK, REWORK
from sealvault.process.stats import summarize


def build_role_stats(cases_flows, calendar):
    roles = {}

    def bucket(role):
        if role is None:
            role = 'unknown'
        if role not in roles:
            roles[role] = {
                'role': role,
                'cases_held': set(),
                'work_seconds': {'natural': [], 'business': []},
                'rework_seconds': {'natural': [], 'business': []},
                'wait_seconds': {'natural': [], 'business': []},
                'handoffs_waiting': 0,
                'rejections_received': 0,
            }
        return roles[role]

    ownership_check = []
    for item in cases_flows:
        flow = item['flow']
        case_id = item['case']['case_id']
        held_roles = set()
        covered_natural = 0
        for interval in flow['owner_intervals']:
            entry = bucket(interval['role'])
            held_roles.add(interval['role'])
            entry['cases_held'].add(case_id)
            natural = calendar.natural_seconds(interval['from'], interval['to'])
            business = calendar.business_seconds(interval['from'], interval['to'])
            entry['work_seconds']['natural'].append(natural)
            entry['work_seconds']['business'].append(business)
            covered_natural += natural
        for role in held_roles:
            bucket(role)
        ownership_check.append({
            'case_id': case_id,
            'held_roles': sorted(role for role in held_roles if role),
            'natural_seconds_partitioned': covered_natural,
        })
        for segment in flow['segments']:
            if segment['stage'] == WAIT:
                entry = bucket(segment.get('destination_role'))
                entry['wait_seconds']['natural'].append(segment['natural_seconds'])
                entry['wait_seconds']['business'].append(segment['business_seconds'])
                entry['handoffs_waiting'] += 1
                if segment['state'] == 'rejected':
                    entry['rejections_received'] += 1
            elif segment['stage'] == REWORK:
                entry = bucket(segment.get('owner_role'))
                entry['rework_seconds']['natural'].append(segment['natural_seconds'])
                entry['rework_seconds']['business'].append(segment['business_seconds'])

    result = []
    for role in sorted(roles):
        entry = roles[role]
        result.append({
            'role': role,
            'cases_held': len(entry['cases_held']),
            'work_seconds': {
                'natural': summarize(entry['work_seconds']['natural']),
                'business': summarize(entry['work_seconds']['business']),
            },
            'rework_seconds': {
                'natural': summarize(entry['rework_seconds']['natural']),
                'business': summarize(entry['rework_seconds']['business']),
            },
            'wait_seconds': {
                'natural': summarize(entry['wait_seconds']['natural']),
                'business': summarize(entry['wait_seconds']['business']),
            },
            'handoffs_waiting': entry['handoffs_waiting'],
            'rejections_received': entry['rejections_received'],
        })
    return {'roles': result, 'ownership_partition': ownership_check}
