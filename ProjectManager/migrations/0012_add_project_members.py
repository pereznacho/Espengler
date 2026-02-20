# Generated manually: Project.members M2M for project members

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ProjectManager', '0011_reportcovertemplate_cover_background_color'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='members',
            field=models.ManyToManyField(
                blank=True,
                help_text='Users with access to this project.',
                related_name='member_projects',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
