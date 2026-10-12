"""Shared code for every Parley service: envelope schema, signing, IDs, time.

Rules for this package (see CLAUDE.md):
- every time is UTC and timezone-aware; use :mod:`parley_common.clock`
- nothing here logs message text, phone numbers, email addresses or private IDs
"""

__version__ = "0.1.0"
