from django.contrib import admin
from django.shortcuts import render
from django.db import models
from .models import Project, Vulnerability, Port, EvidenceImage, Target, ReportTemplate
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.html import format_html
from django import forms
from . import views
from .views import generate_report
from django.forms.models import inlineformset_factory
from django.forms import CheckboxSelectMultiple
from tinymce.widgets import TinyMCE
from .forms import AssignTargetsAndPortsForm
from django.db.models import Case, Value, When
from .models import ReportCoverTemplate



class TargetAdmin(admin.ModelAdmin):  # Cambia el nombre de la clase admin
    list_display = ('ip_address', 'fqdn', 'urlAddress', 'project', 'os', 'owned', 'jumped_from')  # Actualiza los campos según tu modelo Target

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        if db_field.name == "jumped_from":
            kwargs["widget"] = CheckboxSelectMultiple()
        return super().formfield_for_manytomany(db_field, request, **kwargs)

admin.site.register(Target, TargetAdmin)  # Registra el modelo con su clase admin

class ReportTemplateAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.TextField: {'widget': TinyMCE()},
    }

class ImportNessusInline(admin.TabularInline):
    model = Vulnerability
    extra = 0

    def has_add_permission(self, request):
        return False

class VulnerabilityInlineFormSet(inlineformset_factory(Project, Vulnerability, fields='__all__')):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['import_nessus_button'] = forms.CharField(
            widget=forms.TextInput(attrs={'type': 'button', 'value': '+Import Nessus'}),
            required=False
        )

class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 1

    class Media:
        js = ['static/js/custom_import_button.js']

    def import_nessus_button(self, obj):
        url = reverse('admin:import_nessus_file', args=[obj.project.pk])
        return format_html('<a class="button" href="{}">+Import Nessus</a>', url)

    import_nessus_button.short_description = '+Import Nessus'




@admin.register(ReportCoverTemplate)
class ReportCoverTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'tipo_analisis', 'nombre_cliente')




class HostInline(admin.TabularInline):
    model = Target
    extra = 1


class ProjectAdminForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'description', 'start_date', 'end_date', 'language']




class ProjectAdmin(admin.ModelAdmin):
    inlines = [VulnerabilityInline, HostInline]
    form = ProjectAdminForm
    list_display = ('name', 'description', 'start_date', 'end_date', 'language', 'cover_template', 'report_template', 'generate_report_button', 'import_nessus_link')
    actions = ['generate_project_report_action']

    fieldsets = [
        ('Info', {'fields': ['name', 'description', 'start_date', 'end_date', 'language', 'cover_template', 'report_template', 'scope']}),
        ('Vulnerabilities', {'fields': [], 'classes': ['collapse']}),
    ]

    def configurar_tapa_reporte_link(self, obj):
        url = reverse('configurar_tapa_reporte', args=[obj.id])
        return format_html('<a href="{}">Configurar Tapa del Reporte</a>', url)

    configurar_tapa_reporte_link.short_description = 'Configurar Tapa'

    def generate_report_button(self, obj):
        return format_html('<a class="button" href="{}">Generate Report</a>', reverse('generate_report', args=[obj.pk]))

    generate_report_button.short_description = "Generate Report"

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        extra_context['import_nessus_url'] = reverse('import_nessus_file', args=[object_id])
        return super().change_view(request, object_id, form_url, extra_context=extra_context)

    def get_urls(self):
        from django.urls import path

        urls = super().get_urls()
        custom_urls = [
            path('<int:pk>/info/', self.admin_site.admin_view(views.project_info), name='project_info'),
            path('<int:pk>/vulnerabilities/', self.admin_site.admin_view(views.project_vulnerabilities), name='project_vulnerabilities'),
            path('<int:pk>/ports/', self.admin_site.admin_view(views.project_ports), name='project_ports'),
            path('project/generate_report/<int:project_id>/', views.generate_report, name='generate_report'),
            path('<int:pk>/hosts/', self.admin_site.admin_view(self.project_hosts), name='project_hosts'),
        ]
        return custom_urls + urls

    def project_hosts(self, request, pk):
        project = get_object_or_404(Project, pk=pk)
        hosts = Host.objects.filter(project=project)
        return render(request, 'admin/project_hosts.html', {'project': project, 'hosts': hosts})

    def get_fieldsets(self, request, obj=None):
        if obj:
            return super().get_fieldsets(request, obj)
        else:
            return super().get_fieldsets(request, obj)[:-1]

    def generate_project_report_action(self, request, queryset):
        for project in queryset:
            generate_project_report(project.pk)
        self.message_user(request, "Reportes generados exitosamente.")
        return HttpResponseRedirect(reverse('admin:app_project_changelist'))

    generate_project_report_action.short_description = "Generar Informes para Proyectos Seleccionados"

    def import_nessus_link(self, obj):
        url = reverse('import_netsparker_file', args=[obj.id])
        return format_html("<a href='{}'>Import File</a>", url)

    import_nessus_link.short_description = "Import Files"

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "report_template":
            kwargs["queryset"] = ReportTemplate.objects.all()
        elif db_field.name == "cover_template":
            kwargs["queryset"] = ReportCoverTemplate.objects.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)




class AssignTargetsAndPortsForm(forms.Form):
    _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
    targets = forms.ModelMultipleChoiceField(queryset=Target.objects.all(), required=False)
    ports = forms.CharField(max_length=255, help_text="Ingresa los puertos separados por comas")






class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('risk_factor', 'name', 'project', 'hosts_affected', 'port', 'cvss_temporal_score')
    list_filter = ('project', 'risk_factor', 'port')
    actions = ['import_nessus_action', 'assign_targets_and_ports']

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        # Definimos el orden de criticidad
        criticity_order = ['Critical', 'High', 'Medium', 'Low']
        # Ordenamos el queryset por el orden de criticidad definido
        queryset = queryset.order_by(Case(*[When(risk_factor=risk, then=pos) for pos, risk in enumerate(criticity_order)]))
        return queryset



    def assign_targets_and_ports(modeladmin, request, queryset):
        form = AssignTargetsAndPortsForm(initial={'_selected_action': request.POST.getlist('_selected_action')})


        if 'apply' in request.POST:
            form = AssignTargetsAndPortsForm(request.POST)

            if form.is_valid():
                targets = form.cleaned_data['targets']
                ports = form.cleaned_data['ports']
                ports_list = ports.split(',')

                for vulnerability in queryset:
                    vulnerability.targets.add(*targets)  # Asegúrate de que tu modelo pueda manejar esto
                    # Asumiendo que tienes una manera de asignar puertos, modifica según tu modelo
                    vulnerability.ports = ports_list
                    vulnerability.save()

                modeladmin.message_user(request, "Targets y puertos asignados correctamente")
                return HttpResponseRedirect(request.get_full_path())

        if not form:
            form = AssignTargetsAndPortsForm(initial={'_selected_action': request.POST.getlist(admin.ACTION_CHECKBOX_NAME)})

        return render(request, 'admin/assign_targets_and_ports.html', {'items': queryset, 'form': form})

    assign_targets_and_ports.short_description = "Asignar Targets y Puertos"

    def import_nessus_button(self, obj):
        url = reverse('import_nessus_file', args=[obj.project.pk])
        return format_html('<a class="button" href="{}">Import Nessus</a>', url)

    import_nessus_button.short_description = 'Import Nessus'

    def import_nessus_action(self, request, queryset):
        self.message_user(request, "Archivos de Nessus importados con éxito.")
        return HttpResponseRedirect(request.path)

    import_nessus_action.short_description = "Importar archivos de Nessus"

    def project_link(self, obj):
        url = reverse('change_project', args=[obj.project.pk])
        return format_html('<a href="{}">Ver Proyecto</a>', url)

    def show_description(self, obj):
        return obj.description

    show_description.short_description = 'Descripción'

    def show_solution(self, obj):
        return obj.solution

    show_solution.short_description = 'Solución'

    def show_evidence(self, obj):
        return obj.evidence

    show_evidence.short_description = 'Evidencia'

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        import_nessus_url = reverse('import_nessus_file', args=[object_id])
        import_nessus_button = format_html(
            '<a class="button" href="{}">+Import Nessus</a>', import_nessus_url
        )
        extra_context['import_nessus_button'] = import_nessus_button

        return super().change_view(request, object_id, form_url, extra_context=extra_context)

admin.site.register(Project, ProjectAdmin)
admin.site.register(Vulnerability, VulnerabilityAdmin)
admin.site.register(EvidenceImage)
admin.site.register(Port)
admin.site.register(ReportTemplate, ReportTemplateAdmin)
