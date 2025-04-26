from django.db import models

class BackupRestoreEntry(models.Model):
    """ Modelo ficticio para que BackupRestore aparezca en Django Admin """
    name = models.CharField(max_length=255, default="Backup & Restore")

    class Meta:
        verbose_name = "Backup & Restore"
        verbose_name_plural = "Backup & Restore"

    def __str__(self):
        return self.name