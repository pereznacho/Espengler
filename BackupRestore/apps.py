from django.apps import AppConfig

class BackupRestoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'BackupRestore'
    verbose_name = 'Backup & Restore'  # ✅ Esto define cómo se verá en la barra lateral