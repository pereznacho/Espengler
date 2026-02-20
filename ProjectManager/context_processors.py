from django.conf import settings


def app_settings(request):
    return {
        'disable_admin_link': getattr(settings, 'DISABLE_DJANGO_ADMIN', False),
    }
