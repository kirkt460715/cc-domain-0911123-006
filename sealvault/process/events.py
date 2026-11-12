"""Map custody chain rows to timestamped process activities.

Only process metadata is read: action, actor, handoff identifiers and times.
Evidence payloads (entries, digests, titles, reasons, fingerprints) are never
loaded into an analysis activity.
"""

from sealvault.codec import canonical, fail, loads, timestamp
from sealvault.custody import chain

# Custody actions that describe the sealing workflow. Content-editing events
# (entry_attached, classified, ...) are intentionally excluded.
ACTIONS = {
    'created': 'created',
    'handoff_proposed': 'handoff_proposed',
    'handoff_accepted': 'handoff_accepted',
    'handoff_rejected': 'handoff_rejected',
    'handoff_cancelled': 'handoff_cancelled',
    'manifest_prepared': 'manifest_prepared',
    'sealed': 'sealed',
    'abandoned': 'abandoned',
}

DECISIONS = {'handoff_accepted', 'handoff_rejected', 'handoff_cancelled'}
RESUMING = {'handoff_rejected', 'handoff_cancelled'}

# Hard diagnostics mean the process path is untrustworthy: the case is excluded
# from aggregate statistics. Observational diagnostics (e.g. a handoff still
# open at the cutoff) keep the case inside the risk set as right-censored.
HARD_REASONS = {
    'chain_invalid', 'time_invalid', 'time_reversal', 'head_mismatch',
    'chain_empty', 'missing_creation', 'duplicate_handoff_proposal',
    'orphan_handoff_decision', 'duplicate_handoff_decision',
}

# Every field allowed inside a saved analysis envelope. The persistence layer
# rejects anything outside this whitelist so evidence metadata can never leak.
ALLOWED_KEYS = {
    # envelope / identity / calendar
    'abandoned_at', 'accepted', 'activities', 'activity', 'actual_head',
    'actor', 'all', 'analysis_id', 'at', 'business', 'business_seconds',
    'by_creator_role', 'calendar', 'calendar_fingerprint', 'calendar_version',
    'cancel', 'cancelled', 'case_id', 'cases', 'cases_held', 'censorings',
    'censored', 'close', 'completed', 'completed_at', 'completion', 'count',
    'counts', 'cohort', 'cohort_end', 'cohort_start', 'create_after',
    'create_before', 'created_at', 'creator_actor', 'creator_role',
    'criterion', 'cumulative_completed', 'curve', 'cutoff', 'destination',
    'destination_role', 'diagnostics', 'digest', 'elapsed_seconds', 'ended_at',
    'entry_count', 'events', 'excluded', 'failure', 'final_survival', 'from',
    'handoff_decisions', 'handoff_id', 'handoff_wait', 'handoffs_waiting',
    'head', 'head_digest', 'heads', 'held_roles', 'holidays', 'included',
    'is_event', 'km', 'max', 'mean', 'median', 'median_reached', 'min',
    'natural', 'natural_seconds', 'natural_seconds_partitioned', 'offset',
    'open', 'open_at', 'order', 'owner', 'owner_intervals', 'owner_role',
    'ownership_partition', 'p90', 'path', 'path_counts', 'pinned', 'q25',
    'q75', 'quantile_reached', 'quantiles', 'reason_code', 'records',
    'rejections_received', 'rejected', 'rework_after_handoff',
    'rework_seconds', 'risk_set', 'role', 'roles', 'saved_at', 'sealed_at',
    'seals', 'segment', 'segments', 'sequence', 'source', 'stage', 'stages',
    'start_at', 'state', 'statistic', 'status', 'still_waiting', 'summary',
    'survival', 'time', 'to', 'transition', 'transition_counts', 'turnaround',
    'unincluded', 'valid', 'version', 'wait_seconds', 'waiting', 'weekdays',
    'work_seconds',
}

# Evidence-bearing keys that must never appear in an analysis envelope.
FORBIDDEN_KEYS = {'body', 'title', 'reason', 'entries', 'content', 'media_type',
                  'metadata', 'merkle_root', 'body_hash', 'before', 'after',
                  'receipt'}


def actor_role(db, actor_id):
    row = db.one('SELECT role FROM actors WHERE actor_id=?', (actor_id,))
    return row['role'] if row else None


def _dedupe(items):
    seen = set()
    result = []
    for item in items:
        marker = canonical(item)
        if marker not in seen:
            seen.add(marker)
            result.append(item)
    return result


def extract_case(db, case_id, cutoff, pinned_head):
    """Build activities, paired handoffs and diagnostics for one case.

    Returns a case dict; ``valid`` is False when chain integrity, head or
    ordering problems make the process path untrustworthy.
    """
    cutoff = timestamp(cutoff)
    diagnostic = []
    case_row = db.one('SELECT case_id,owner,state,created_at FROM cases WHERE case_id=?', (case_id,))
    if case_row is None:
        fail('case_missing', 'Evidence case does not exist')

    try:
        verification = chain.verify(db, case_id)
    except Exception as exc:  # noqa: BLE001 - diagnostics must not crash analysis
        verification = None
        diagnostic.append({'case_id': case_id, 'reason_code': 'chain_invalid',
                           'failure': type(exc).__name__})

    rows = db.all('SELECT sequence,action,actor,body,at,entry_hash FROM custody '
                  'WHERE case_id=? ORDER BY sequence', (case_id,))
    heads = [row['entry_hash'] for row in rows]
    actual_head = heads[-1] if heads else None

    if verification is None:
        previous_time = ''
        for row in rows:
            try:
                canonical_at = timestamp(row['at'])
            except Exception:  # noqa: BLE001
                diagnostic.append({'case_id': case_id, 'reason_code': 'time_invalid',
                                   'sequence': row['sequence']})
                continue
            if canonical_at < previous_time:
                diagnostic.append({'case_id': case_id, 'reason_code': 'time_reversal',
                                   'sequence': row['sequence'], 'at': canonical_at})
            previous_time = canonical_at

    if pinned_head is not None and pinned_head != actual_head:
        diagnostic.append({'case_id': case_id, 'reason_code': 'head_mismatch',
                           'pinned': pinned_head, 'actual_head': actual_head})
    if not rows:
        diagnostic.append({'case_id': case_id, 'reason_code': 'chain_empty'})
        return _invalid(db, case_id, case_row, cutoff, pinned_head, actual_head,
                        0, diagnostic)
    if rows[0]['action'] != 'created':
        diagnostic.append({'case_id': case_id, 'reason_code': 'missing_creation',
                           'sequence': rows[0]['sequence']})

    activities = []
    handoff_index = {}
    handoff_rows = {row['handoff_id']: row for row in db.all(
        'SELECT handoff_id,source,destination,state FROM handoffs WHERE case_id=?', (case_id,))}
    role_lookup = {row['actor_id']: row['role'] for row in db.all(
        'SELECT actor_id,role FROM actors')}
    order = 0
    previous_time = ''
    for row in rows:
        try:
            canonical_at = timestamp(row['at'])
        except Exception:  # noqa: BLE001 - keep analyzing, flag the bad row
            diagnostic.append({'case_id': case_id, 'reason_code': 'time_invalid',
                               'sequence': row['sequence']})
            continue
        if canonical_at < previous_time:
            diagnostic.append({'case_id': case_id, 'reason_code': 'time_reversal',
                               'sequence': row['sequence'], 'at': canonical_at})
        previous_time = canonical_at
        if canonical_at > cutoff:
            break
        action = row['action']
        if action not in ACTIONS:
            continue
        body = loads(row['body']) if action.startswith('handoff_') else {}
        handoff_id = body.get('handoff_id') if action.startswith('handoff_') else None
        activity = {
            'case_id': case_id,
            'sequence': row['sequence'],
            'order': order,
            'activity': ACTIONS[action],
            'at': canonical_at,
            'actor': row['actor'],
        }
        if handoff_id is not None:
            activity['handoff_id'] = handoff_id
            reference = handoff_rows.get(handoff_id)
            if reference is not None:
                activity['source'] = reference['source']
                activity['destination'] = reference['destination']
        activities.append(activity)
        order += 1
        if handoff_id is not None:
            pair = handoff_index.setdefault(handoff_id, {'handoff_id': handoff_id,
                                                         'proposal': None, 'decision': None})
            if action == 'handoff_proposed':
                if pair['proposal'] is not None:
                    diagnostic.append({'case_id': case_id, 'reason_code': 'duplicate_handoff_proposal',
                                       'handoff_id': handoff_id, 'sequence': row['sequence']})
                pair['proposal'] = activity
            elif action in DECISIONS:
                if pair['proposal'] is None:
                    diagnostic.append({'case_id': case_id, 'reason_code': 'orphan_handoff_decision',
                                       'handoff_id': handoff_id, 'sequence': row['sequence']})
                if pair['decision'] is not None:
                    diagnostic.append({'case_id': case_id, 'reason_code': 'duplicate_handoff_decision',
                                       'handoff_id': handoff_id, 'sequence': row['sequence']})
                pair['decision'] = activity
        if action in RESUMING and handoff_id is not None:
            # Re-entry into the editable state is a derived activity kept in the
            # path as rework evidence; it never collapses into first-pass flow.
            activities.append({
                'case_id': case_id,
                'sequence': row['sequence'],
                'order': order,
                'activity': 'editable_resumed',
                'at': canonical_at,
                'actor': row['actor'],
                'handoff_id': handoff_id,
            })
            order += 1

    # Same instant follows chain order: activities were emitted in sequence
    # order, and editable_resumed carries the next order of its parent event.
    activities.sort(key=lambda item: (item['at'], item['order']))

    observational = []
    for pair in handoff_index.values():
        if pair['proposal'] is None:
            diagnostic.append({'case_id': case_id, 'reason_code': 'orphan_handoff_decision',
                               'handoff_id': pair['handoff_id']})
        elif pair['decision'] is None:
            observational.append({'case_id': case_id, 'reason_code': 'handoff_open_at_cutoff',
                                  'handoff_id': pair['handoff_id'],
                                  'open_at': pair['proposal']['at']})
    # Decisions whose handoff id has no paired proposal on the observed chain,
    # including ids that never created an index entry of their own.
    for activity in activities:
        if activity['activity'] not in DECISIONS:
            continue
        pair = handoff_index.get(activity['handoff_id'])
        if pair is None or pair.get('proposal') is None:
            diagnostic.append({'case_id': case_id, 'reason_code': 'orphan_handoff_decision',
                               'handoff_id': activity['handoff_id'],
                               'sequence': activity['sequence']})
    diagnostic = _dedupe(diagnostic)

    created = next((item for item in activities if item['activity'] == 'created'), None)
    if created is None:
        diagnostic.append({'case_id': case_id, 'reason_code': 'missing_creation'})

    sealed = next((item for item in activities if item['activity'] == 'sealed'), None)
    abandoned = next((item for item in activities if item['activity'] == 'abandoned'), None)
    state = 'sealed' if sealed else ('abandoned' if abandoned else 'open')
    hard_codes = {item['reason_code'] for item in diagnostic}
    return {
        'case_id': case_id,
        'valid': not hard_codes.intersection(HARD_REASONS),
        'creator_actor': case_row['owner'],
        'creator_role': actor_role(db, case_row['owner']),
        'created_at': created['at'] if created else case_row['created_at'],
        'state': state,
        'sealed_at': sealed['at'] if sealed else None,
        'abandoned_at': abandoned['at'] if abandoned else None,
        'cutoff': cutoff,
        'pinned_head': pinned_head,
        'head': actual_head,
        'entry_count': len(rows),
        'activities': activities,
        'handoffs': list(handoff_index.values()),
        'diagnostics': diagnostic + observational,
        '_role_lookup': role_lookup,
    }


def _invalid(db, case_id, case_row, cutoff, pinned_head, actual_head, entry_count, diagnostic):
    return {
        'case_id': case_id,
        'valid': False,
        'creator_actor': case_row['owner'],
        'creator_role': actor_role(db, case_row['owner']),
        'created_at': case_row['created_at'],
        'state': case_row['state'],
        'sealed_at': None,
        'abandoned_at': None,
        'cutoff': cutoff,
        'pinned_head': pinned_head,
        'head': actual_head,
        'entry_count': entry_count,
        'activities': [],
        'handoffs': [],
        'diagnostics': diagnostic,
    }
