# Generated manually: background_image and customer_image_scale for ReportCoverTemplate

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ProjectManager', '0008_reportcovertemplate_subtitle_consultant'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportcovertemplate',
            name='background_image',
            field=models.ImageField(blank=True, help_text='Optional background for the cover.', null=True, upload_to='imagenes/'),
        ),
        migrations.AddField(
            model_name='reportcovertemplate',
            name='customer_image_scale',
            field=models.PositiveSmallIntegerField(default=100, help_text='Scale of the main (customer) image as percentage (10-100). 100 = full width.'),
        ),
    ]
