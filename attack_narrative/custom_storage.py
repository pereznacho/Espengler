# attack_narrative/custom_storage.py
import os
from django.core.files.storage import FileSystemStorage
from django.conf import settings


class WriteupImageStorage(FileSystemStorage):
    def __init__(self, writeup_title=None, *args, **kwargs):
        self.writeup_title = writeup_title or "generic"
        location = os.path.join(settings.PROTECTED_MEDIA_ROOT, self.writeup_title)
        super().__init__(location=location, base_url=f"{settings.PROTECTED_MEDIA_URL}{self.writeup_title}/")

    def get_available_name(self, name, max_length=None):
        # Evita conflictos sobrescribiendo
        return super().get_available_name(name, max_length=max_length)