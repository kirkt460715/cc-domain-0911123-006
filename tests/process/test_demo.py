import unittest

from examples.process_demo import run as run_demo
from sealvault.codec import VaultError
from sealvault.process.analytics import ProcessAnalytics
from tests.support import Case


class ProcessDemoTests(Case):
    def test_drill_covers_rejection_open_handoff_and_censoring(self):
        result = run_demo()
        self.assertTrue(result['ok'])
        self.assertEqual(result['counts'], {'cohort': 2, 'included': 2,
                                            'excluded': 0, 'seals': 1, 'censored': 1})
        self.assertEqual(result['handoff_decisions'],
                         {'accepted': 1, 'rejected': 1, 'cancelled': 0, 'waiting': 1})
        self.assertEqual(result['km']['risk_set'], 2)
        self.assertEqual(result['km']['censored'], 1)
        self.assertTrue(result['km']['median_reached'])
        # The open handoff is the observational diagnostic from the waiting case.
        self.assertEqual(len(result['diagnostics']), 1)
        self.assertEqual(result['diagnostics'][0]['case_id'], 'waiting')
        # Business and natural waiting time are both reported.
        waiting = result['still_waiting']
        self.assertEqual(waiting['natural']['max'], 399600)
        self.assertEqual(waiting['business']['max'], 28800)

    def test_drill_save_persists_inside_its_vault(self):
        result = run_demo(save=True)
        self.assertFalse(result['saved']['duplicate'])
        self.assertEqual(result['saved']['analysis_id'], 'drill-process-analysis')
        self.assertIsNotNone(result['calendar_fingerprint'])

    def test_invalid_calendar_is_rejected(self):
        from examples.context import build
        vault, _ = build()
        try:
            desk = ProcessAnalytics(vault.db)
            bad_calendar = {'version': 'bad', 'offset': '+08:00', 'weekdays': [0, 11],
                            'open': '09:00', 'close': '17:00', 'holidays': []}
            with self.assertRaises(VaultError) as info:
                desk.run('bad', '2026-11-10T00:00:00Z', bad_calendar,
                         '2026-11-05T00:00:00Z', '2026-11-06T00:00:00Z')
            self.assertEqual(info.exception.code, 'calendar_weekdays')
        finally:
            vault.close()


if __name__ == '__main__':
    unittest.main()
