#!/usr/bin/env python
"""
------------------------------------------------------------
  File        : manage.py
  Author      : Nandan A M
  Description : !!not to change or reuse without my concern!!
  Created On  : 22-Mar-2025
  Version     : 13.5
------------------------------------------------------------
"""

RUNTIME_DISABLE_DEMO = True
if RUNTIME_DISABLE_DEMO:
    raise SystemExit('Demo build: Django manage disabled')

"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_threat_detection.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
