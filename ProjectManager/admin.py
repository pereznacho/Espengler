from django.contrib import admin
from django.http import HttpResponse
from django.urls import path
from django.shortcuts import get_object_or_404
from django.db import models
from django.template.loader import get_template
from django.utils.html import format_html
from django.forms import CheckboxSelectMultiple
from django.middleware.csrf import get_token
from .forms import ProjectAdminForm
from django.utils.safestring import mark_safe
from django.urls import reverse
from tinymce.widgets import TinyMCE
from .models import (
    Project,
    Target,
    Vulnerability,
    ReportTemplate,
    ReportCoverTemplate,
    Port,
    EvidenceImage,
)
from .forms import ProjectAdminForm, TargetAdminForm
import json
from attack_narrative.models import Writeup


class TargetInline(admin.TabularInline):
    model = Target
    extra = 0


class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    show_change_link = True


class ProjectAdmin(admin.ModelAdmin):
    inlines = [VulnerabilityInline, TargetInline]
    form = ProjectAdminForm
    exclude = ("graphmap_display", )
    filter_horizontal = ('attack_narratives',)
    readonly_fields = ('graphmap_display',)

    class Media:
        css = {
            'all': ('css/custom.css',)
        }

    fieldsets = [
        ("Info", {
            "fields": [
                "name",
                "description",
                "start_date",
                "end_date",
                "language",
                "cover_template",
                "report_template",
                "scope",
                "attack_narratives",
            ]
        }),
        ("GraphMap", {
            "fields": ["graphmap_display"],
        }),
    ]

    readonly_fields = ["graphmap_display"]

    # 🔥 Volvemos a incluir `list_display`
    list_display = (
        "name", "description", "start_date", "end_date", "language",
        "cover_template", "report_template", "generate_report_button",
        "import_nessus_link"  # ✅ Ahora sí está definido correctamente
    )

    def generate_report_button(self, obj):
        url = reverse("generate_report", args=[obj.pk])
        return format_html(
            '''
            <button onclick="postToGenerateReport('{}')" style="background-color: #00bc8c; color: white; padding: 8px 12px; border-radius: 5px; border: none; cursor: pointer; font-weight: bold;">
                Generate Report
            </button>
            <script>
                function postToGenerateReport(url) {{
                    const form = document.createElement("form");
                    form.method = "POST";
                    form.action = url;
                    form.target = "_blank";

                    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
                    const csrfField = document.createElement("input");
                    csrfField.type = "hidden";
                    csrfField.name = "csrfmiddlewaretoken";
                    csrfField.value = csrfToken;

                    form.appendChild(csrfField);
                    document.body.appendChild(form);
                    form.submit();
                }}
            </script>
            ''',
            url
        )

    def get_queryset(self, request):
        """Guardar `request` en `self.request` para poder acceder al CSRF token en `generate_report_button`."""
        self.request = request
        return super().get_queryset(request)

    def import_nessus_link(self, obj):
        """Botón estilizado para importar archivos Nessus con el mismo diseño que Generate Report."""
        if obj and obj.id:
            url = reverse('import_netsparker_file', args=[obj.id])
            return format_html(
                '''
                <a href="{}" style="background-color: #00bc8c; color: white; padding: 8px 12px; border-radius: 5px; border: none; cursor: pointer; font-weight: bold; text-decoration: none; display: inline-block; text-align: center;">
                    + Import File
                </a>
                ''',
                url
            )
        return "-"

    import_nessus_link.short_description = "+Import File"

    def attack_narratives(self, obj):
        """Campo virtual que lista los Writeups asociados al proyecto"""
        count = obj.attack_narratives_attack_narrative.count()
        if count == 0:
            return "No Writeups"
        else:
            writeups = obj.attack_narratives_attack_narrative.all()
            return mark_safe("<br>".join([f"• {w.title}" for w in writeups]))



    def graphmap_display(self, obj):
        """Link button to the standalone Vis.js GraphMap page."""
        if not obj or not obj.pk:
            return "Save the project first to view the GraphMap."
        url = reverse('graph_map', args=[obj.pk])
        return format_html(
            '<div style="padding: 12px 0;">'
            '<a href="{}" target="_blank" '
            'style="background: linear-gradient(135deg, #00cc33, #00ff41); color: #000; '
            'padding: 10px 24px; border-radius: 8px; text-decoration: none; '
            'font-weight: 700; letter-spacing: 1px; display: inline-block; '
            'transition: all 0.25s; box-shadow: 0 4px 12px rgba(0,255,65,0.25);">'
            '<i class="fas fa-project-diagram"></i>&nbsp; Open GraphMap'
            '</a>'
            '</div>',
            url
        )

admin.site.register(Project, ProjectAdmin)

@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.TextField: {"widget": TinyMCE()},
    }
    list_display = ("name", "used_by_project", "used_by_customer")

    def used_by_project(self, obj):
        project = Project.objects.filter(report_template=obj).first()
        return project.name if project else "-"
    used_by_project.short_description = "Project"

    def used_by_customer(self, obj):
        try:
            project = Project.objects.filter(report_template=obj).first()
            if project and project.cover_template and hasattr(project.cover_template, 'nombre_cliente'):
                return project.cover_template.nombre_cliente
        except Exception as e:
            return f"Error: {e}"
        return "-"




class TargetAdmin(admin.ModelAdmin):
    form = TargetAdminForm
    list_display = ("ip_address", "fqdn", "urlAddress", "project", "os", "owned", "jumped_from")
    list_filter = ('project', 'owned')

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "jumped_from":
            kwargs["widget"] = CheckboxSelectMultiple()
        return super().formfield_for_manytomany(db_field, request, **kwargs)


admin.site.register(Target, TargetAdmin)


@admin.register(ReportCoverTemplate)
class ReportCoverTemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "analisys_type", "customer_name", "edit_visually_link")

    def edit_visually_link(self, obj):
        from django.urls import reverse
        from django.utils.html import format_html
        url = reverse("visual_cover_designer_template", args=[obj.pk])
        return format_html('<a class="button" href="{}">Visual designer</a>', url)
    edit_visually_link.short_description = "Cover"

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ("port_and_protocol", "banner_summary", "target_host_display", "project_name")
    search_fields = ("port_number", "protocol", "banner", "target__fqdn", "target__urlAddress", "target__ip_address", "target__project__name")

    def port_and_protocol(self, obj):
        return f"{obj.port_number}/{obj.protocol}"
    port_and_protocol.short_description = "Port"

    def banner_summary(self, obj):
        return (obj.banner[:50] + "...") if obj.banner and len(obj.banner) > 50 else obj.banner or "-"
    banner_summary.short_description = "Banner"

    def target_host_display(self, obj):
        if obj.target:
            return obj.target.fqdn or obj.target.urlAddress or str(obj.target.ip_address)
        return "-"
    target_host_display.short_description = "Host"

    def project_name(self, obj):
        return obj.target.project.name if obj.target and obj.target.project else "-"
    project_name.short_description = "Project"


class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("risk_factor", "name", "project", "hosts_affected", "port", "cvss_temporal_score")
    list_filter = ("project", "risk_factor", "port")


    def import_nessus_file(self, request):
        """Vista para importar archivos Nessus"""
        return HttpResponse("Nessus file import would be handled here.")

@admin.register(EvidenceImage)
class EvidenceImageAdmin(admin.ModelAdmin):
    list_display = ("image_preview", "description", "project")
    search_fields = ("description", "project__name")

    def image_preview(self, obj):
        if obj.image:
            return format_html('<img src="{}" width="100" />', obj.image.url)
        return "No Image"
    image_preview.short_description = "Preview"

admin.site.register(Vulnerability, VulnerabilityAdmin)

