"""Five-field cron expressions evaluated in UTC. Standard library only.

Fields: minute (0-59), hour (0-23), day of month (1-31), month (1-12 or jan-dec) and
day of week (0-7 or sun-sat, 0 and 7 are Sunday). Each field accepts `*`, values,
ranges `a-b`, steps `*/n`, `a-b/n` or `a/n`, and comma-separated lists. When both day
fields are restricted, a day matches if either matches, as in Vixie cron.
"""
import re
from datetime import datetime, timedelta

MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}
WEEKDAYS = {name: number for number, name in enumerate(("sun", "mon", "tue", "wed", "thu", "fri", "sat"))}
FIELDS = (("minute", 0, 59, {}), ("hour", 0, 23, {}), ("day of month", 1, 31, {}),
          ("month", 1, 12, MONTHS), ("day of week", 0, 7, WEEKDAYS))
NUMBER = re.compile(r"[0-9]{1,2}")
SEARCH_DAYS = 366 * 5


def _value(text, label, names):
    lowered = text.lower()
    if lowered in names:
        return names[lowered]
    if NUMBER.fullmatch(text):
        return int(text)
    raise ValueError(f"invalid {label} value: {text!r}")


def _field(text, label, low, high, names):
    values = set()
    for part in text.split(","):
        if not part:
            raise ValueError(f"empty list item in {label}")
        base, slash, step_text = part.partition("/")
        step = 1
        if slash:
            if not NUMBER.fullmatch(step_text) or int(step_text) == 0:
                raise ValueError(f"invalid step in {label}: {part!r}")
            step = int(step_text)
        if base == "*":
            start, end = low, high
        elif "-" in base:
            first, _, last = base.partition("-")
            start, end = _value(first, label, names), _value(last, label, names)
        else:
            start = _value(base, label, names)
            end = high if slash else start
        if not low <= start <= high or not low <= end <= high:
            raise ValueError(f"{label} out of range {low}-{high}: {part!r}")
        if start > end:
            raise ValueError(f"descending range in {label}: {part!r}")
        values.update(range(start, end + 1, step))
    return frozenset(values)


class CronExpression:
    """A parsed cron expression with UTC next-run calculation at minute resolution."""

    def __init__(self, text):
        if not isinstance(text, str) or len(text) > 128:
            raise ValueError("cron expression must be a string of at most 128 characters")
        parts = text.split()
        if len(parts) != 5:
            raise ValueError("cron expression needs five fields: minute hour day-of-month month day-of-week")
        self.text = " ".join(parts)
        parsed = [_field(part, *spec) for part, spec in zip(parts, FIELDS)]
        self.minutes, self.hours, self.days, self.months, weekdays = parsed
        self.weekdays = frozenset(0 if day == 7 else day for day in weekdays)
        self.day_or = not parts[2].startswith("*") and not parts[4].startswith("*")
        self.next_after(datetime(2000, 1, 1))

    def __str__(self):
        return self.text

    def _day_matches(self, moment):
        in_month = moment.day in self.days
        in_week = (moment.weekday() + 1) % 7 in self.weekdays
        return (in_month or in_week) if self.day_or else (in_month and in_week)

    def matches(self, moment):
        return (moment.minute in self.minutes and moment.hour in self.hours
                and moment.month in self.months and self._day_matches(moment))

    def next_after(self, moment):
        """First matching minute strictly after `moment` (tzinfo is preserved)."""
        current = moment.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = current + timedelta(days=SEARCH_DAYS)
        while current <= limit:
            if current.month not in self.months:
                year, month = (current.year + 1, 1) if current.month == 12 else (current.year, current.month + 1)
                current = current.replace(year=year, month=month, day=1, hour=0, minute=0)
            elif not self._day_matches(current):
                current = (current + timedelta(days=1)).replace(hour=0, minute=0)
            elif current.hour not in self.hours:
                current = (current + timedelta(hours=1)).replace(minute=0)
            elif current.minute not in self.minutes:
                current += timedelta(minutes=1)
            else:
                return current
        raise ValueError(f"cron expression never matches: {self.text}")


def next_run(text, after):
    return CronExpression(text).next_after(after)
