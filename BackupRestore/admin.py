from django.contrib import admin
from django.urls import path, reverse
from django.template.response import TemplateResponse
from django.utils.html import format_html
from .models import BackupRestoreEntry  # Modelo ficticio solo para mostrar en el admin
from django.http import HttpResponseRedirect


class BackupRestoreAdmin(admin.ModelAdmin):
    """ Admin panel para exportar e importar toda la DB + archivos """
    change_list_template = "BackupRestore/dashboard.html"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('dashboard/', self.admin_site.admin_view(self.dashboard_view), name="backup_dashboard"),
        ]
        return custom_urls + urls

    def dashboard_view(self, request):
        context = self.admin_site.each_context(request)
        context["export_url"] = reverse("export_data")
        context["import_url"] = reverse("import_data")
        return TemplateResponse(request, "BackupRestore/dashboard.html", context)


admin.site.site_header = "EspEngler Admin"
admin.site.site_title = "EspEngler Admin"
admin.site.index_title = "Bienvenido a EspEngler"

admin.site.register(BackupRestoreEntry, BackupRestoreAdmin)