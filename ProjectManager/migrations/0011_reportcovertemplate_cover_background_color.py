# Generated manually: cover_background_color for ReportCoverTemplate

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ProjectManager', '0010_reportcovertemplate_cover_layout'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportcovertemplate',
            name='cover_background_color',
            field=models.CharField(blank=True, default='#FFFFFF', help_text='Color de fondo de la página de portada (hex, ej. #FFFFFF blanco).', max_length=7),
        ),
    ]
