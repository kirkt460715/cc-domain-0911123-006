import unittest

from sealvault.codec import VaultError, canonical, digest
from sealvault.custody import actors, chain
from sealvault.process.analytics import ProcessAnalytics, enforce_privacy
from sealvault.process import events as events_module
from sealvault.service import Vault
from tests.support import Clock

CALENDAR = {
    'version': 'cal-1', 'offset': '+08:00', 'weekdays': [0, 1, 2, 3, 4],
    'open': '09:00', 'close': '17:00', 'holidays': ['2026-11-06'],
}
AFTER = '2026-11-05T00:00:00Z'
BEFORE = '2026-11-06T00:00:00Z'
CUTOFF = '2026-11-10T00:00:00Z'


class ProcessCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.vault = Vault(clock=self.clock)
        self.db = self.vault.db
        for identity, role in [('collector', 'collector'), ('other', 'collector'),
                               ('keeper', 'custodian'), ('reviewer', 'custodian'),
                               ('auditor', 'auditor')]:
            actors.register(self.db, identity, role)
        self.desk = ProcessAnalytics(self.db)

    def tearDown(self):
        self.vault.close()

    def create_case(self, case_id, created, owner='collector'):
        self.clock.set(created)
        self.vault.cases.create(case_id, 'synthetic', owner)
        stored = self.vault.objects.put(b'synthetic bytes')
        self.vault.cases.attach(
            case_id, 1, owner,
            {'path': 'data.txt', 'digest': stored['digest'], 'size': stored['size'],
             'media_type': 'text/plain', 'metadata': {'synthetic': True}})
        return self.vault.cases.get(case_id)

    def propose(self, handoff_id, case_id, source, destination, at):
        self.clock.set(at)
        revision = self.vault.cases.get(case_id)['revision']
        return self.vault.handoffs.propose(
            handoff_id, case_id, source, destination, revision,
            '2026-12-31T00:00:00Z', 'synthetic handoff')

    def reject(self, handoff_id, destination, at):
        self.clock.set(at)
        self.vault.handoffs.reject(handoff_id, destination, 'synthetic rejection')

    def cancel(self, handoff_id, source, at):
        self.clock.set(at)
        self.vault.handoffs.cancel(handoff_id, source, 'synthetic cancel')

    def accept(self, handoff_id, destination, at):
        self.clock.set(at)
        proposal = self.vault.handoffs.get(handoff_id)
        return self.vault.handoffs.accept(handoff_id, destination,
                                          proposal['fingerprint'], 'receipt-' + handoff_id)

    def seal_case(self, case_id, owner, reviewer, at, manifest_id=None):
        self.clock.set(at)
        manifest_id = manifest_id or 'seal-' + case_id
        revision = self.vault.cases.get(case_id)['revision']
        self.vault.seals.prepare(manifest_id, case_id, revision, owner)
        return self.vault.seals.seal(manifest_id, reviewer, '2027-01-01T00:00:00Z')

    def run_analysis(self, analysis_id='analysis-1', cutoff=CUTOFF, heads=None,
                     calendar_config=None, after=AFTER, before=BEFORE):
        return self.desk.run(analysis_id, cutoff, calendar_config or CALENDAR,
                             after, before, heads)

    def data(self, envelope):
        return envelope['payload']['data']


class CohortAndPathTests(ProcessCase):
    def test_cohort_uses_first_creation_window_and_keeps_unsealed_in_risk_set(self):
        self.create_case('closed', '2026-11-05T08:00:00Z')
        self.create_case('waiting', '2026-11-05T08:01:00Z')
        self.propose('h-closed', 'closed', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.accept('h-closed', 'keeper', '2026-11-06T02:00:00Z')
        self.seal_case('closed', 'keeper', 'reviewer', '2026-11-06T03:00:00Z')
        self.propose('h-wait', 'waiting', 'collector', 'keeper', '2026-11-05T09:30:00Z')

        envelope = self.run_analysis()
        data = self.data(envelope)
        self.assertEqual(data['counts'], {'cohort': 2, 'included': 2, 'excluded': 0,
                                          'seals': 1, 'censored': 1})
        km = data['summary']['km']['natural']
        self.assertEqual(km['risk_set'], 2)
        self.assertEqual(km['events'], 1)
        self.assertEqual(km['censored'], 1)
        self.assertTrue(km['median_reached'])
        # Event time traces back to the sealed case and the censored case.
        event_cases = [case for row in km['curve'] if row['events'] for case in row['cases']]
        self.assertEqual(event_cases, ['closed'])

    def test_case_created_outside_window_is_excluded(self):
        self.create_case('inside', '2026-11-05T08:00:00Z')
        self.create_case('outside', '2026-11-06T08:00:00Z')
        data = self.data(self.run_analysis())
        self.assertEqual([case['case_id'] for case in data['cases']], ['inside'])
        self.assertEqual(data['counts']['cohort'], 1)

    def test_rejection_retry_and_resume_remain_in_actual_path(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.reject('h1', 'keeper', '2026-11-05T10:00:00Z')
        self.propose('h2', 'case-a', 'collector', 'keeper', '2026-11-09T02:00:00Z')
        self.accept('h2', 'keeper', '2026-11-09T03:00:00Z')
        self.seal_case('case-a', 'keeper', 'reviewer', '2026-11-09T04:00:00Z')

        data = self.data(self.run_analysis())
        case = next(case for case in data['cases'] if case['case_id'] == 'case-a')
        self.assertEqual(case['path'], [
            'created', 'handoff_proposed', 'handoff_rejected', 'editable_resumed',
            'handoff_proposed', 'handoff_accepted', 'manifest_prepared', 'sealed'])
        # Retry is not collapsed into first-pass flow: two proposals remain.
        self.assertEqual(case['path'].count('handoff_proposed'), 2)
        stages = {row['stage']: row for row in data['summary']['stages']}
        self.assertIsNotNone(stages['rework']['statistic'])
        self.assertEqual(stages['handoff_wait']['statistic']['natural']['count'], 2)
        transitions = {row['transition']: row['count']
                       for row in data['summary']['transition_counts']}
        self.assertEqual(transitions['handoff_rejected->editable_resumed'], 1)
        self.assertEqual(transitions['editable_resumed->handoff_proposed'], 1)

    def test_handoff_wait_pairs_by_handoff_id_not_next_event(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('alpha', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.propose('beta', 'case-a', 'collector', 'other', '2026-11-05T09:30:00Z')
        self.cancel('beta', 'collector', '2026-11-05T10:00:00Z')
        self.accept('alpha', 'keeper', '2026-11-05T11:00:00Z')

        data = self.data(self.run_analysis())
        case = next(case for case in data['cases'] if case['case_id'] == 'case-a')
        waits = {segment['handoff_id']: segment for segment in case['segments']
                 if segment['stage'] == 'handoff_wait'}
        # alpha closes on its own acceptance (2h), beta on its own cancel (0.5h).
        self.assertEqual(waits['alpha']['natural_seconds'], 7200)
        self.assertEqual(waits['alpha']['state'], 'accepted')
        self.assertEqual(waits['beta']['natural_seconds'], 1800)
        self.assertEqual(waits['beta']['state'], 'cancelled')
        self.assertNotEqual(waits['alpha']['ended_at'], waits['beta']['ended_at'])

    def test_same_instant_events_follow_chain_sequence(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        # Proposal and rejection at the same timestamp: chain order must win.
        self.reject('h1', 'keeper', '2026-11-05T09:00:00Z')
        data = self.data(self.run_analysis())
        case = next(case for case in data['cases'] if case['case_id'] == 'case-a')
        self.assertEqual([item['activity'] for item in case['activities']][:3],
                         ['created', 'handoff_proposed', 'handoff_rejected'])

    def test_reject_then_cancel_keeps_single_rework_window_until_acceptance(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.reject('h1', 'keeper', '2026-11-05T10:00:00Z')
        self.propose('h2', 'case-a', 'collector', 'other', '2026-11-05T11:00:00Z')
        self.cancel('h2', 'collector', '2026-11-05T12:00:00Z')
        self.propose('h3', 'case-a', 'collector', 'keeper', '2026-11-06T02:00:00Z')
        self.accept('h3', 'keeper', '2026-11-06T03:00:00Z')
        self.seal_case('case-a', 'keeper', 'reviewer', '2026-11-06T04:00:00Z')

        data = self.data(self.run_analysis())
        case = next(case for case in data['cases'] if case['case_id'] == 'case-a')
        rework = [segment for segment in case['segments'] if segment['stage'] == 'rework']
        # One continuous rework window from the latest resume to the next
        # handoff proposal; the proposal-to-acceptance gap is handoff wait.
        self.assertEqual(len(rework), 1)
        self.assertEqual(rework[0]['rework_after_handoff'], 'h2')
        self.assertEqual(rework[0]['start_at'], '2026-11-05T12:00:00.000000Z')
        self.assertEqual(rework[0]['ended_at'], '2026-11-06T02:00:00.000000Z')
        # The two failed handoffs and the accepted one are all present.
        waits = [segment for segment in case['segments'] if segment['stage'] == 'handoff_wait']
        self.assertEqual([segment['state'] for segment in waits],
                         ['rejected', 'cancelled', 'accepted'])


class SurvivalTests(ProcessCase):
    def test_median_not_reached_is_reported_not_replaced_by_mean(self):
        # Two cases, none sealed: KM curve stays at 1.0, median must be None.
        for index in range(2):
            cid = 'open-' + str(index)
            self.create_case(cid, f'2026-11-05T08:0{index}:00Z')
            self.propose('h-' + cid, cid, 'collector', 'keeper', '2026-11-05T09:00:00Z')
        data = self.data(self.run_analysis())
        km = data['summary']['km']['natural']
        self.assertEqual(km['risk_set'], 2)
        self.assertEqual(km['events'], 0)
        self.assertEqual(km['censored'], 2)
        self.assertFalse(km['median_reached'])
        self.assertIsNone(km['median'])
        self.assertEqual(km['final_survival'], 1.0)
        self.assertIsNone(km['quantiles']['median'])
        self.assertFalse(km['quantile_reached']['q75'])

    def test_km_risk_set_shrinks_after_events_and_censorings(self):
        # Three cases: one sealed early, one censored, one sealed late.
        self.create_case('a', '2026-11-05T08:00:00Z')
        self.create_case('b', '2026-11-05T08:10:00Z')
        self.create_case('c', '2026-11-05T08:20:00Z')
        self.propose('ha', 'a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.accept('ha', 'keeper', '2026-11-05T10:00:00Z')
        self.seal_case('a', 'keeper', 'reviewer', '2026-11-05T11:00:00Z')
        self.propose('hb', 'b', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.propose('hc', 'c', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.accept('hc', 'keeper', '2026-11-06T02:00:00Z')
        self.seal_case('c', 'keeper', 'reviewer', '2026-11-06T04:00:00Z')
        data = self.data(self.run_analysis())
        km = data['summary']['km']['natural']
        self.assertEqual(km['risk_set'], 3)
        self.assertEqual(km['events'], 2)
        self.assertEqual(km['censored'], 1)
        risk_sets = [row['risk_set'] for row in km['curve']]
        self.assertEqual(risk_sets[0], 3)
        self.assertTrue(km['median_reached'])


class RoleAndDiagnosticTests(ProcessCase):
    def test_role_attribution_partitions_owner_time_without_double_count(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.accept('h1', 'keeper', '2026-11-05T11:00:00Z')
        self.seal_case('case-a', 'keeper', 'reviewer', '2026-11-05T12:00:00Z')
        data = self.data(self.run_analysis())
        partition = data['roles']['ownership_partition'][0]
        turnaround = next(case['turnaround'] for case in data['cases']
                          if case['case_id'] == 'case-a')
        self.assertEqual(partition['natural_seconds_partitioned'],
                         turnaround['natural_seconds'])
        roles = {row['role']: row for row in data['roles']['roles']}
        self.assertEqual(roles['collector']['cases_held'], 1)
        self.assertEqual(roles['custodian']['cases_held'], 1)
        # The waiting handoff is attributed to the destination role, not source.
        self.assertEqual(roles['custodian']['handoffs_waiting'], 1)
        self.assertEqual(roles['collector']['handoffs_waiting'], 0)

    def test_repeated_rejections_and_open_handoff_are_traceable(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.reject('h1', 'keeper', '2026-11-05T10:00:00Z')
        self.propose('h2', 'case-a', 'collector', 'keeper', '2026-11-06T02:00:00Z')
        self.reject('h2', 'keeper', '2026-11-06T03:00:00Z')
        self.propose('h3', 'case-a', 'collector', 'keeper', '2026-11-09T01:00:00Z')
        data = self.data(self.run_analysis())
        case = next(case for case in data['cases'] if case['case_id'] == 'case-a')
        waits = [segment for segment in case['segments'] if segment['stage'] == 'handoff_wait']
        self.assertEqual([segment['state'] for segment in waits],
                         ['rejected', 'rejected', 'waiting'])
        open_wait = waits[-1]
        self.assertEqual(open_wait['handoff_id'], 'h3')
        self.assertTrue(open_wait['open'])
        diagnostic = data['diagnostics'][0]
        self.assertEqual(diagnostic['reason_code'], 'handoff_open_at_cutoff')
        self.assertEqual(diagnostic['handoff_id'], 'h3')
        # Statistics trace back to concrete chain sequences.
        self.assertTrue(all(1 <= item['sequence'] for item in case['activities']))
        roles = {row['role']: row for row in data['roles']['roles']}
        self.assertEqual(roles['custodian']['rejections_received'], 2)

    def test_time_reversal_is_a_hard_diagnostic_and_excludes_case(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        # Tamper with a custody timestamp directly to force a reversal.
        self.db.execute("UPDATE custody SET at='2026-11-04T00:00:00.000000Z' "
                        "WHERE case_id='case-a' AND sequence=2")
        data = self.data(self.run_analysis())
        self.assertEqual(data['counts']['included'], 0)
        self.assertEqual(data['counts']['excluded'], 1)
        codes = {item['reason_code'] for item in data['diagnostics']}
        self.assertIn('chain_invalid', codes)
        self.assertIn('time_reversal', codes)

    def test_pinned_head_mismatch_is_diagnosed(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        actual_head = chain.history(self.db, 'case-a')[-1]['entry_hash']
        # Partial pinning is rejected: the head must be fixed for every case.
        with self.assertRaises(VaultError) as partial:
            self.run_analysis(heads={'other-case': '0' * 64})
        self.assertEqual(partial.exception.code, 'analysis_heads')
        # A fully pinned but wrong head becomes a hard diagnostic, not a crash.
        envelope = self.desk.run('analysis-x', CUTOFF, CALENDAR, AFTER, BEFORE,
                                 heads={'case-a': 'f' * 64})
        data = self.data(envelope)
        self.assertEqual(data['counts']['excluded'], 1)
        self.assertTrue(any(item['reason_code'] == 'head_mismatch'
                            for item in data['diagnostics']))
        # The correct head keeps the case in the analysis.
        good = self.data(self.run_analysis('analysis-y', heads={'case-a': actual_head}))
        self.assertEqual(good['counts']['excluded'], 0)


class PersistenceAndPrivacyTests(ProcessCase):
    def test_snapshot_is_immutable_and_later_seal_keeps_old_analysis(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        first = self.run_analysis('frozen')
        saved = self.desk.save(first)
        self.assertFalse(saved['duplicate'])
        loaded = self.desk.get('frozen')
        self.assertEqual(loaded['sha256'], first['sha256'])

        # The case gets sealed after the analysis; the saved snapshot must not change.
        self.accept('h1', 'keeper', '2026-11-06T02:00:00Z')
        self.seal_case('case-a', 'keeper', 'reviewer', '2026-11-06T03:00:00Z')
        again = self.desk.save(first)
        self.assertTrue(again['duplicate'])
        self.assertEqual(self.desk.get('frozen')['sha256'], first['sha256'])
        stored = self.data(self.desk.get('frozen'))
        self.assertEqual(stored['counts']['seals'], 0)
        self.assertEqual(stored['counts']['censored'], 1)

        # Reusing the id with a different snapshot is rejected.
        second = self.run_analysis('frozen')
        with self.assertRaises(VaultError) as info:
            self.desk.save(second)
        self.assertEqual(info.exception.code, 'analysis_exists')

    def test_saving_same_snapshot_is_idempotent(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        envelope = self.run_analysis('once')
        first = self.desk.save(envelope)
        second = self.desk.save(envelope)
        self.assertFalse(first['duplicate'])
        self.assertTrue(second['duplicate'])
        self.assertEqual(first['digest'], second['digest'])

    def test_envelope_carries_only_process_metadata(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        envelope = self.run_analysis()
        # The serialized envelope never contains evidence fields or content.
        text = canonical(envelope)
        for forbidden in ('synthetic bytes', 'entry_attached', 'media_type',
                          'merkle_root', 'body_hash', 'metadata', 'receipt-'):
            self.assertNotIn(forbidden, text)
        enforce_privacy(envelope['payload']['data'])
        with self.assertRaises(VaultError) as info:
            enforce_privacy({'case_id': 'case-a', 'entries': [{'digest': 'x'}]})
        self.assertEqual(info.exception.code, 'analysis_privacy')
        with self.assertRaises(VaultError):
            enforce_privacy({'case_id': 'case-a', 'unknown_dynamic_key': 1})

    def test_chain_head_is_pinned_into_snapshot(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        envelope = self.run_analysis()
        data = self.data(envelope)
        head = chain.history(self.db, 'case-a')[-1]['entry_hash']
        self.assertEqual(data['heads'][0]['head'], head)
        self.assertEqual(data['heads'][0]['pinned'], head)
        self.assertEqual(data['head_digest'], digest({'case-a': head}))

    def test_orphan_handoff_decision_is_a_hard_diagnostic(self):
        from sealvault.process import events as events_module
        self.create_case('orphan-case', '2026-11-05T08:00:00Z')
        self.propose('h1', 'orphan-case', 'collector', 'keeper', '2026-11-05T09:00:00Z')
        self.reject('h1', 'keeper', '2026-11-05T10:00:00Z')
        # Re-key the rejection body to a handoff id without any proposal.
        from sealvault.codec import canonical as canon, loads
        row = self.db.one("SELECT sequence,body FROM custody WHERE case_id='orphan-case' "
                          "AND action='handoff_rejected'")
        body = loads(row['body'])
        body['handoff_id'] = 'missing-proposal'
        self.db.execute('UPDATE custody SET body=? WHERE case_id=? AND sequence=?',
                        (canon(body), 'orphan-case', row['sequence']))
        case = events_module.extract_case(self.db, 'orphan-case', CUTOFF, None)
        self.assertFalse(case['valid'])
        codes = {item['reason_code'] for item in case['diagnostics']}
        # The hash failure and the orphan pairing are both reported.
        self.assertIn('chain_invalid', codes)
        self.assertIn('orphan_handoff_decision', codes)
        # And the aggregate run excludes the case from statistics.
        data = self.data(self.run_analysis(after='2026-11-05T00:00:00Z',
                                           before='2026-11-06T00:00:00Z'))
        self.assertEqual(data['counts']['excluded'], 1)

    def test_routes_are_available_through_vault_execute(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        result = self.vault.execute({'operation': 'analysis.run', 'arguments': {
            'analysis_id': 'via-execute', 'cutoff': CUTOFF,
            'calendar_config': CALENDAR, 'create_after': AFTER,
            'create_before': BEFORE}})
        self.assertEqual(result['payload']['data']['counts']['cohort'], 1)
        commands = {item['operation'] for item in self.vault.commands()}
        self.assertIn('analysis.run', commands)
        self.assertIn('analysis.save', commands)
        self.assertIn('analysis.get', commands)


class BusinessTimeAndTurnaroundTests(ProcessCase):
    def test_business_and_natural_time_reported_together(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        # Proposal at local 16:00, acceptance at next Monday local 10:00,
        # crossing the Friday holiday and the weekend.
        self.propose('h1', 'case-a', 'collector', 'keeper', '2026-11-05T08:00:00Z')
        self.accept('h1', 'keeper', '2026-11-09T02:00:00Z')
        data = self.data(self.run_analysis())
        wait = next(segment for case in data['cases'] for segment in case['segments']
                    if segment['stage'] == 'handoff_wait')
        # Natural elapsed is 90 hours; the Friday holiday and weekend add zero
        # business time, leaving Thursday's last hour and Monday's first hour.
        self.assertEqual(wait['natural_seconds'], 90 * 3600)
        self.assertEqual(wait['business_seconds'], 2 * 3600)
        turnaround = data['summary']['turnaround']['all']['natural']
        self.assertEqual(turnaround['count'], 1)
        # Handoff wait and turnaround are summarized separately.
        wait_summary = data['summary']['handoff_wait']['all']['natural']
        self.assertEqual(wait_summary['max'], 90 * 3600)

    def test_calendar_fingerprint_changes_with_calendar_version(self):
        self.create_case('case-a', '2026-11-05T08:00:00Z')
        first = self.data(self.run_analysis('v1'))
        second_calendar = dict(CALENDAR, version='cal-2', holidays=['2026-11-09'])
        second = self.data(self.run_analysis('v2', calendar_config=second_calendar))
        self.assertNotEqual(first['calendar_fingerprint'], second['calendar_fingerprint'])
        self.assertEqual(first['calendar']['version'], 'cal-1')
        self.assertEqual(second['calendar']['version'], 'cal-2')


if __name__ == '__main__':
    unittest.main()
