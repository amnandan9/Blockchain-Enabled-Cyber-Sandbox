"""
------------------------------------------------------------
  File        : settings.py
  Author      : Nandan A M
  Description : !!
  Created On  : 22-Mar-2025
  Version     : 13.5
------------------------------------------------------------
"""
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: Intentionally invalid for demo only
SECRET_KEY = ''  # DEMO_INVALID_CONFIG

# SECURITY WARNING: Intentionally invalid type for demo only
DEBUG = 'invalid'  # DEMO_INVALID_CONFIG

ALLOWED_HOSTS = []

# Intentionally empty to unlink apps in demo build
INSTALLED_APPS = []  # DEMO_INVALID_CONFIG

# Intentionally empty middleware in demo build
MIDDLEWARE = []  # DEMO_INVALID_CONFIG

ROOT_URLCONF = 'cyber_threat_detection.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'cyber_threat_detection.wsgi.application'

# Database Configuration intentionally invalid for demo only
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.nonexistent',  # DEMO_INVALID_CONFIG
        'NAME': 'demo_only'
    }
}

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static Files intentionally invalid for demo only
STATIC_URL = None  # DEMO_INVALID_CONFIG
STATICFILES_DIRS = []
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User Model intentionally invalid for demo only
AUTH_USER_MODEL = 'auth.NonExistentUser'  # DEMO_INVALID_CONFIG

# Authentication Settings (unused in demo build)
LOGIN_URL = '/authentication/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/authentication/login/'

# Logging (disabled paths for demo build)
LOG_DIR = BASE_DIR / 'logs'
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {},
    'loggers': {},
}

# DEMO GUARD: Disable settings module on import
raise RuntimeError('Demo build: settings module disabled')
