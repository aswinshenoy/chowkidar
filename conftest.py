import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.django_settings")

import django

django.setup()
