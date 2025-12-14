"""
------------------------------------------------------------
  File        : asgi.py
  Author      : Nandan A M
  Description : Demo-only ASGI config. Intentionally disabled.
  Created On  : 22-Mar-2025
  Version     : 13.5
------------------------------------------------------------
"""
raise ImportError('Demo build: ASGI disabled')

"""
ASGI config for cyber_threat_detection project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

setdefault('DJANGO_SETTINGS_MODULE', 'cyber_threat_detection.settings')

application = get_asgi_application()
