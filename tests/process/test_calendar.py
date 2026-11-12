import unittest

from sealvault.codec import VaultError
from sealvault.process.calendar import BusinessCalendar


def calendar(**overrides):
    config = {
        'version': 'cal-1', 'offset': '+08:00', 'weekdays': [0, 1, 2, 3, 4],
        'open': '09:00', 'close': '17:00', 'holidays': ['2026-11-06'],
    }
    config.update(overrides)
    return BusinessCalendar.from_config(config)


class BusinessCalendarTests(unittest.TestCase):
    def test_natural_time_ignores_calendar(self):
        cal = calendar()
        # 09:00 to 11:00 local: two hours either way.
        self.assertEqual(cal.natural_seconds('2026-11-05T01:00:00Z', '2026-11-05T03:00:00Z'), 7200)
        self.assertEqual(cal.business_seconds('2026-11-05T01:00:00Z', '2026-11-05T03:00:00Z'), 7200)

    def test_overnight_gap_counts_zero_business_time(self):
        cal = calendar()
        start = '2026-11-05T08:30:00Z'   # 16:30 local
        end = '2026-11-06T01:30:00Z'     # 09:30 local next day
        # 17 hours natural; only Monday's last 30 business minutes remain.
        self.assertEqual(cal.natural_seconds(start, end), 17 * 3600)
        self.assertEqual(cal.business_seconds(start, end), 1800)

    def test_weekend_and_holiday_are_excluded(self):
        cal = calendar(holidays=['2026-11-06'])
        # Wednesday 17:00 local -> Monday 10:00 local. Thursday is a holiday,
        # Friday a workday, Sat/Sun the weekend.
        start = '2026-11-04T09:00:00Z'   # Wed 17:00 local (closing instant)
        end = '2026-11-09T02:00:00Z'     # Mon 10:00 local
        # Friday contributes 8 business hours, Monday one hour.
        self.assertEqual(cal.business_seconds(start, end), 9 * 3600)
        self.assertGreater(cal.natural_seconds(start, end), 4 * 24 * 3600)

    def test_holiday_window_is_skipped(self):
        cal = calendar(holidays=['2026-11-05'])  # Thursday holiday
        start = '2026-11-04T09:00:00Z'   # Wed 17:00 local
        end = '2026-11-06T01:00:00Z'     # Fri 09:00 local
        self.assertEqual(cal.business_seconds(start, end), 0)

    def test_invalid_weekday_rejected(self):
        with self.assertRaises(VaultError) as info:
            calendar(weekdays=[0, 11])
        self.assertEqual(info.exception.code, 'calendar_weekdays')
        with self.assertRaises(VaultError):
            calendar(weekdays=[])
        with self.assertRaises(VaultError):
            calendar(weekdays=[1.0])

    def test_invalid_window_and_offset_rejected(self):
        with self.assertRaises(VaultError):
            calendar(open='17:00', close='09:00')
        with self.assertRaises(VaultError):
            calendar(offset='+25:00')
        with self.assertRaises(VaultError):
            calendar(holidays=['2026-11-06', '2026-11-06'])
        with self.assertRaises(VaultError):
            calendar(holidays=['not-a-date'])

    def test_fingerprint_pins_calendar_version(self):
        first = calendar()
        second = calendar(version='cal-2')
        self.assertNotEqual(first.fingerprint(), second.fingerprint())
        third = calendar(holidays=['2026-11-09'])
        self.assertNotEqual(first.fingerprint(), third.fingerprint())
        self.assertEqual(first.config()['weekdays'], [0, 1, 2, 3, 4])

    def test_reversed_interval_rejected(self):
        cal = calendar()
        with self.assertRaises(VaultError):
            cal.business_seconds('2026-11-05T03:00:00Z', '2026-11-05T01:00:00Z')


if __name__ == '__main__':
    unittest.main()
