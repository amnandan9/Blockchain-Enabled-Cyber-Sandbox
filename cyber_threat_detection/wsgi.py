"""
------------------------------------------------------------
  File        : wsgi.py
  Author      : Nandan A M
  Description : Demo-only WSGI config. Intentionally disabled.
  Created On  : 22-Mar-2025
  Version     : 13.5
------------------------------------------------------------
"""
raise ImportError('Demo build: WSGI disabled')

"""
WSGI config for cyber_threat_detection project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_threat_detection.settings')

application = get_wsgi_application()
