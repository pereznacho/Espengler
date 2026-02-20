# Generated manually for ReportCoverTemplate subtitle and consultant_name

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ProjectManager', '0007_reporttemplate_background_color_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportcovertemplate',
            name='subtitle',
            field=models.CharField(blank=True, help_text='Optional subtitle (e.g. Report type).', max_length=255),
        ),
        migrations.AddField(
            model_name='reportcovertemplate',
            name='consultant_name',
            field=models.CharField(blank=True, help_text='Optional consultant or team name.', max_length=255),
        ),
    ]
