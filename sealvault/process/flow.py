"""Build actual activity paths, process segments and role attribution.

Segments never infer a handoff end from "the next arbitrary event": every
handoff wait is opened by its handoff_proposed activity and closed only by the
accepted/rejected/cancelled activity carrying the same handoff_id. Retries,
rejections and editable_resumed activities stay in the path as rework.
"""

from sealvault.process.stats import summarize

WAIT = 'handoff_wait'
WORK = 'case_work'
REWORK = 'rework'
SEALING = 'sealing'
STAGES = (WAIT, WORK, REWORK, SEALING)


def _duration(calendar, start, end):
    return {
        'natural_seconds': calendar.natural_seconds(start, end),
        'business_seconds': calendar.business_seconds(start, end),
    }


def build_flow(case, calendar):
    """Return path, segments, transitions and owner timeline for a valid case."""
    activities = case['activities']
    cutoff = case['cutoff']
    # A sealed or abandoned case stops accumulating time at its terminal event;
    # later chain activity (e.g. post-seal attestations) is outside this process.
    terminal_at = case['sealed_at'] or case['abandoned_at']
    horizon = terminal_at or cutoff
    roles = case.get('_role_lookup', {})

    def role_of(actor):
        return roles.get(actor)

    path = [item['activity'] for item in activities]
    open_proposals = {}
    segments = []
    owner_intervals = []
    current_owner = None
    owner_since = None
    last_activity = None
    last_owner_activity = None
    prepared_activity = None
    transitions = {}

    def add_transition(source, target):
        if source is None:
            return
        key = source + '->' + target
        transitions[key] = transitions.get(key, 0) + 1

    def close_work(end_activity, end_at):
        if last_owner_activity is None or end_at <= last_owner_activity['at']:
            return
        segments.append({
            'case_id': case['case_id'],
            'stage': WORK,
            'from': last_owner_activity['activity'],
            'to': end_activity,
            'start_at': last_owner_activity['at'],
            'ended_at': end_at,
            'owner': current_owner,
            'owner_role': role_of(current_owner),
            **_duration(calendar, last_owner_activity['at'], end_at),
        })

    for activity in activities:
        name = activity['activity']
        at = activity['at']
        add_transition(last_activity, name)
        if name == 'created':
            current_owner = activity['actor']
            owner_since = at
            last_owner_activity = activity
        elif name == 'handoff_proposed':
            close_work(name, at)
            open_proposals[activity['handoff_id']] = activity
        elif name in {'handoff_accepted', 'handoff_rejected', 'handoff_cancelled'}:
            proposal = open_proposals.pop(activity['handoff_id'], None)
            start_at = proposal['at'] if proposal else None
            destination = activity.get('destination') or activity['actor']
            end_state = {'handoff_accepted': 'accepted',
                         'handoff_rejected': 'rejected',
                         'handoff_cancelled': 'cancelled'}[name]
            segment = {
                'case_id': case['case_id'],
                'stage': WAIT,
                'handoff_id': activity['handoff_id'],
                'start_at': start_at,
                'ended_at': at,
                'source': activity.get('source'),
                'destination': destination,
                'destination_role': role_of(destination),
                'state': end_state,
                'open': False,
            }
            if start_at is not None:
                segment.update(_duration(calendar, start_at, at))
            segments.append(segment)
            if name == 'handoff_accepted':
                owner_intervals.append({
                    'actor': current_owner, 'role': role_of(current_owner),
                    'from': owner_since, 'to': at,
                })
                current_owner = activity['actor']
                owner_since = at
            last_owner_activity = activity
        elif name == 'editable_resumed':
            # Re-entry into the editable state restarts owner work as rework.
            last_owner_activity = activity
        elif name == 'manifest_prepared':
            close_work(name, at)
            prepared_activity = activity
        elif name in {'sealed', 'abandoned'}:
            if name == 'sealed' and prepared_activity is not None and prepared_activity['at'] <= at:
                segments.append({
                    'case_id': case['case_id'],
                    'stage': SEALING,
                    'from': 'manifest_prepared',
                    'to': 'sealed',
                    'start_at': prepared_activity['at'],
                    'ended_at': at,
                    'owner': current_owner,
                    'owner_role': role_of(current_owner),
                    **_duration(calendar, prepared_activity['at'], at),
                })
                prepared_activity = None
            else:
                close_work(name, at)
        last_activity = name

    # Open handoff waits at cutoff are paired by handoff_id, never guessed.
    for handoff_id, proposal in open_proposals.items():
        destination = proposal.get('destination')
        segments.append({
            'case_id': case['case_id'],
            'stage': WAIT,
            'handoff_id': handoff_id,
            'start_at': proposal['at'],
            'ended_at': horizon,
            'source': proposal.get('source'),
            'destination': destination,
            'destination_role': role_of(destination),
            'state': 'waiting',
            'open': True,
            **_duration(calendar, proposal['at'], horizon),
        })

    # A still-open owner work interval at the horizon remains observable.
    if terminal_at is None and last_owner_activity is not None and horizon > last_owner_activity['at']:
        segments.append({
            'case_id': case['case_id'],
            'stage': WORK,
            'from': last_owner_activity['activity'],
            'to': 'cutoff',
            'start_at': last_owner_activity['at'],
            'ended_at': horizon,
            'owner': current_owner,
            'owner_role': role_of(current_owner),
            'open': True,
            **_duration(calendar, last_owner_activity['at'], horizon),
        })

    owner_intervals.append({
        'actor': current_owner, 'role': role_of(current_owner),
        'from': owner_since, 'to': horizon,
    })

    _mark_rework(segments, activities, horizon)

    completed = case['sealed_at'] is not None
    end_at = terminal_at or cutoff
    turnaround = {
        'case_id': case['case_id'],
        'start_at': case['created_at'],
        'ended_at': end_at,
        'completed': completed,
        'censored': not completed,
        **_duration(calendar, case['created_at'], end_at),
    }
    return {
        'path': path,
        'segments': segments,
        'transitions': transitions,
        'owner_intervals': owner_intervals,
        'turnaround': turnaround,
    }


def _mark_rework(segments, activities, horizon):
    """Owner work after the latest editable_resumed event is rework.

    A rework window opens on every rejection/cancel-derived editable_resumed
    and closes at the next successful handoff acceptance; if none follows it
    stays open through the observation horizon. Rejections while a window is
    already open simply move its start to the newest resume event.
    """
    resumed_times = sorted(item['at'] for item in activities
                           if item['activity'] == 'editable_resumed')
    accepted_times = sorted(item['at'] for item in activities
                            if item['activity'] == 'handoff_accepted')
    if not resumed_times:
        return

    def window_for(start_at):
        end_at = next((moment for moment in accepted_times if moment > start_at), horizon)
        return start_at, end_at

    windows = []
    for resumed_at in resumed_times:
        start_at, end_at = window_for(resumed_at)
        if windows and windows[-1][1] == end_at:
            windows[-1] = (resumed_at, end_at)
        else:
            windows.append((start_at, end_at))

    for segment in segments:
        if segment['stage'] != WORK:
            continue
        for start_at, end_at in windows:
            if segment['start_at'] >= start_at and segment['ended_at'] <= end_at:
                segment['stage'] = REWORK
                segment['rework_after_handoff'] = next(
                    item['handoff_id'] for item in activities
                    if item['activity'] == 'editable_resumed' and item['at'] == start_at)
                break


def aggregate(cases_flows):
    """Roll per-case flows up into path counts, transition and stage stats."""
    path_counts = {}
    transition_counts = {}
    stage_values = {stage: {'natural_seconds': [], 'business_seconds': []} for stage in STAGES}
    waiting = []
    handoff_decisions = {'accepted': 0, 'rejected': 0, 'cancelled': 0, 'waiting': 0}
    for item in cases_flows:
        path = tuple(item['flow']['path'])
        path_counts[path] = path_counts.get(path, 0) + 1
        for key, count in item['flow']['transitions'].items():
            transition_counts[key] = transition_counts.get(key, 0) + count
        for segment in item['flow']['segments']:
            stage = segment['stage']
            if 'natural_seconds' in segment:
                stage_values[stage]['natural_seconds'].append(segment['natural_seconds'])
                stage_values[stage]['business_seconds'].append(segment['business_seconds'])
            if stage == WAIT:
                handoff_decisions[segment['state']] += 1
                if segment['open']:
                    waiting.append({
                        'case_id': segment['case_id'],
                        'handoff_id': segment['handoff_id'],
                        'open_at': segment['start_at'],
                        'cutoff': segment['ended_at'],
                        'natural_seconds': segment['natural_seconds'],
                        'business_seconds': segment['business_seconds'],
                    })
    stages = []
    for stage in STAGES:
        natural = stage_values[stage]['natural_seconds']
        business = stage_values[stage]['business_seconds']
        stages.append({'stage': stage,
                       'statistic': None if not natural else {
                           'natural': summarize(natural),
                           'business': summarize(business),
                       }})
    return {
        'path_counts': [{'path': list(path), 'count': count}
                        for path, count in sorted(path_counts.items(), key=lambda kv: (-kv[1], kv[0]))],
        'transition_counts': [{'transition': key, 'count': transition_counts[key]}
                              for key in sorted(transition_counts)],
        'stages': stages,
        'handoff_decisions': handoff_decisions,
        'waiting': sorted(waiting, key=lambda row: (row['case_id'], row['handoff_id'])),
    }
