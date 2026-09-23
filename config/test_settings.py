"""Django settings for the automated test suite.

``config.settings`` reads its configuration from the environment at import
time, and pytest-django imports the settings module before any ``conftest.py``
runs. This module sets fixed test values first, then loads the real settings.
The fixed values override the shell environment and any local ``.env`` file,
so tests are hermetic and never touch a real Canvas instance.
"""

import os

from cryptography.fernet import Fernet

_TEST_ENV_DEFAULTS: dict[str, str] = {
    "DJANGO_SECRET_KEY": "test-secret",
    "DJANGO_DEBUG": "true",
    "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "CANVAS_BASE_URL": "https://canvas.example.test",
    "CANVAS_CLIENT_ID": "10000000000001",
    "CANVAS_CLIENT_SECRET": "test-client-secret",
    "CANVAS_REDIRECT_URI": "http://localhost:8000/oauth/callback/",
    "CANVAS_SCOPES": "url:GET|/api/v1/courses",
}

for _name, _value in _TEST_ENV_DEFAULTS.items():
    os.environ[_name] = _value

from config.settings import *  # noqa: E402, F403
