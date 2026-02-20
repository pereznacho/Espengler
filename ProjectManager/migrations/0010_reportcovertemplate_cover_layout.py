# Generated manually: cover_layout for ReportCoverTemplate

from django.db import migrations, models


def default_layout():
    return {
        "header_left": {"left": 2, "top": 2, "width": 18, "height": 8},
        "header_right": {"left": 80, "top": 2, "width": 18, "height": 8},
        "title_block": {"left": 5, "top": 22, "width": 90, "height": 25},
        "customer_image": {"left": 10, "top": 55, "width": 80, "height": 35},
    }


class Migration(migrations.Migration):

    dependencies = [
        ('ProjectManager', '0009_reportcovertemplate_background_image_scale'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportcovertemplate',
            name='cover_layout',
            field=models.JSONField(blank=True, default=dict, help_text='Layout positions: header_left, header_right, title_block, customer_image with left, top, width, height (%).'),
        ),
    ]
