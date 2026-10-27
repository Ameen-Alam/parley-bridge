"""Shared code for every Parley service: envelope schema, signing, IDs, time, and the
one reader of ``PARLEY_`` configuration (:mod:`parley_common.env`, T-0047).

Rules for this package (see CLAUDE.md):
- every time is UTC and timezone-aware; use :mod:`parley_common.clock`
- nothing here logs message text, phone numbers, email addresses or private IDs
"""

__version__ = "0.1.0"
