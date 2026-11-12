"""Process analytics over custody chains and handoff records.

The package never reads evidence contents. It maps custody chain events to
timestamped process activities, pairs handoff waits by handoff_id, and produces
cycle-time, rework, role-attribution and Kaplan-Meier completion statistics.
"""
