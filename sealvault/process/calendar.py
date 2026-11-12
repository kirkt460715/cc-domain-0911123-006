import datetime
import re

from sealvault.codec import canonical, digest, fail, text, timestamp

_OFFSET = re.compile(r'([+-])(\d{2}):(\d{2})$')
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}$')
_TIME = re.compile(r'(\d{2}):(\d{2})$')
MAX_DAYS = 3660


class BusinessCalendar:
    """Fixed-offset business calendar with one daily [open, close) window."""

    def __init__(self, version, offset, weekdays, open_time, close_time, holidays):
        self.version = text(version, 120)
        self.timezone = self._parse_offset(offset)
        self.offset = offset
        if not isinstance(weekdays, list) or not weekdays:
            fail('calendar_weekdays', 'weekdays must be a nonempty list')
        if any(type(item) is not int or not 0 <= item <= 6 for item in weekdays):
            fail('calendar_weekdays', 'weekdays must be integers 0..6 (Monday=0)')
        if len(set(weekdays)) != len(weekdays):
            fail('calendar_weekdays', 'weekdays must be unique')
        self.weekdays = sorted(weekdays)
        self.open = self._parse_clock(open_time, 'open')
        self.close = self._parse_clock(close_time, 'close')
        if self.open >= self.close:
            fail('calendar_window', 'Daily business window requires open < close')
        if not isinstance(holidays, list) or any(not isinstance(item, str) or not _DATE.match(item) for item in holidays):
            fail('calendar_holidays', 'holidays must be YYYY-MM-DD date strings')
        if len(set(holidays)) != len(holidays):
            fail('calendar_holidays', 'holidays must be unique')
        self.holidays = sorted(holidays)
        self._holiday_dates = {datetime.date.fromisoformat(item) for item in holidays}

    @staticmethod
    def _parse_offset(value):
        if value == 'Z':
            return datetime.timezone.utc
        match = _OFFSET.match(value or '')
        if not match:
            fail('calendar_offset', 'Offset must be Z or a fixed +HH:MM/-HH:MM offset')
        sign, hours, minutes = match.groups()
        hours, minutes = int(hours), int(minutes)
        if hours > 23 or minutes > 59:
            fail('calendar_offset', 'Offset hours or minutes are out of range')
        delta = datetime.timedelta(hours=hours, minutes=minutes)
        return datetime.timezone(delta if sign == '+' else -delta)

    @staticmethod
    def _parse_clock(value, name):
        match = _TIME.match(value or '')
        if not match:
            fail('calendar_window', f'{name} must use HH:MM')
        hour, minute = int(match.group(1)), int(match.group(2))
        if hour > 23 or minute > 59:
            fail('calendar_window', f'{name} time is out of range')
        return datetime.time(hour, minute)

    @classmethod
    def from_config(cls, config):
        if isinstance(config, BusinessCalendar):
            return config
        if not isinstance(config, dict):
            fail('calendar', 'Calendar configuration must be an object')
        try:
            return cls(config['version'], config['offset'], config['weekdays'],
                       config['open'], config['close'], config.get('holidays', []))
        except KeyError as exc:
            fail('calendar', 'Calendar configuration misses a field', field=exc.args[0])

    def config(self):
        return {
            'version': self.version,
            'offset': self.offset,
            'weekdays': self.weekdays,
            'open': f'{self.open.hour:02d}:{self.open.minute:02d}',
            'close': f'{self.close.hour:02d}:{self.close.minute:02d}',
            'holidays': self.holidays,
        }

    def fingerprint(self):
        return digest(canonical(self.config()))

    @staticmethod
    def _instant(value):
        return datetime.datetime.fromisoformat(timestamp(value).replace('Z', '+00:00'))

    def natural_seconds(self, start, end):
        return int(round((self._instant(end) - self._instant(start)).total_seconds()))

    def business_seconds(self, start, end):
        """Elapsed business time. Overnight gaps, weekends and holidays count zero."""
        start_utc = self._instant(start)
        end_utc = self._instant(end)
        if end_utc < start_utc:
            fail('calendar_interval', 'Interval ends before it starts')
        start_local = start_utc.astimezone(self.timezone)
        end_local = end_utc.astimezone(self.timezone)
        total = 0
        day = start_local.date()
        guard = 0
        while day <= end_local.date():
            guard += 1
            if guard > MAX_DAYS:
                fail('calendar_range', 'Interval exceeds the supported calendar range')
            if day.weekday() in self.weekdays and day not in self._holiday_dates:
                window_start = datetime.datetime.combine(day, self.open, self.timezone)
                window_end = datetime.datetime.combine(day, self.close, self.timezone)
                lo = max(start_local, window_start)
                hi = min(end_local, window_end)
                if hi > lo:
                    total += int(round((hi - lo).total_seconds()))
            day += datetime.timedelta(days=1)
        return total
