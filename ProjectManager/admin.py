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
from django.views.decorators.csrf import csrf_exempt



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
            'all': ('css/custom.css',)  # Ruta correcta
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

    @csrf_exempt
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
        if not obj:
            return "No project data available."

        targets = Target.objects.filter(project=obj)

        base_static_url = "/static/images/"
        attack_icon = f"{base_static_url}attack.png"
        owned_icon = f"{base_static_url}imac1.png"
        default_icon = f"{base_static_url}imac.png"

        nodes = [{
            "id": "pentester",
            "label": "Pentester",
            "image": attack_icon,
            "x": 400,
            "y": 300
        }]
        node_ids = {"pentester"}
        edges = []

        for i, target in enumerate(targets):
            node_id = str(target.id)
            label = target.ip_address or target.fqdn or target.urlAddress or "Unnamed"
            x = target.x_position if target.x_position is not None else 200 + (i * 100)
            y = target.y_position if target.y_position is not None else 100 + (i * 50)

            nodes.append({
                "id": node_id,
                "label": label,
                "image": owned_icon if target.owned else default_icon,
                "x": x,
                "y": y
            })
            node_ids.add(node_id)

        existing_node_ids = {str(n["id"]) for n in nodes}

        for target in targets:
            target_id = str(target.id)
            if target_id not in existing_node_ids:
                continue

            if target.owned and not target.jumped_from:
                source_id = "pentester"
            elif target.jumped_from_id and str(target.jumped_from_id) in existing_node_ids:
                source_id = str(target.jumped_from_id)
            else:
                continue

            if source_id in existing_node_ids and source_id != target_id:
                edges.append({"source": source_id, "target": target_id})

        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)
        save_url_base = reverse('save_node_position', args=[0]).replace('/0/', '')

        graphmap_html = f"""
        <script src="https://d3js.org/d3.v7.min.js"></script>

        <div style="width: 100%; display: flex; flex-direction: column; align-items: center;">
            <div id="graphmap-container" 
                style="width: 850px; height: 650px; border: 1px solid #ddd; border-radius: 8px; padding: 10px; background-color: #f9f9f9;">
            </div>
        </div>

        <script>
            document.addEventListener("DOMContentLoaded", function () {{
                function updateGraph() {{
                    var container = document.getElementById("graphmap-container");
                    if (!container) {{
                        console.error("GraphMap container not found.");
                        return;
                    }}

                    d3.select("#graphmap-container").selectAll("*").remove();

                    const nodes = {nodes_json};
                    const edges = {edges_json};
                    const width = container.offsetWidth;
                    const height = container.offsetHeight;

                    const svg = d3.select("#graphmap-container").append("svg")
                        .attr("width", width)
                        .attr("height", height)
                        .call(d3.zoom().scaleExtent([0.5, 2]).on("zoom", function (event) {{
                            svg.attr("transform", event.transform);
                        }}))
                        .append("g");

                    nodes.forEach(n => {{
                        if (typeof n.x === "number" && typeof n.y === "number") {{
                            n.fx = n.x;
                            n.fy = n.y;
                        }}
                    }});

                    const simulation = d3.forceSimulation(nodes)
                        .force("link", d3.forceLink(edges).id(d => d.id).distance(100))
                        .force("charge", d3.forceManyBody().strength(-50))
                        .force("center", d3.forceCenter(width / 2, height / 2))
                        .force("collide", d3.forceCollide().radius(40));

                    const link = svg.append("g")
                        .selectAll("line")
                        .data(edges)
                        .enter().append("line")
                        .attr("stroke-width", 2)
                        .attr("stroke", "#999");

                    const node = svg.append("g")
                        .selectAll("image")
                        .data(nodes)
                        .enter().append("image")
                        .attr("xlink:href", d => d.image)
                        .attr("width", 40)
                        .attr("height", 40)
                        .attr("x", d => d.x - 20)
                        .attr("y", d => d.y - 20)
                        .call(d3.drag()
                            .on("start", dragStarted)
                            .on("drag", dragged)
                            .on("end", dragEnded));

                    const labels = svg.append("g")
                        .selectAll("text")
                        .data(nodes)
                        .enter().append("text")
                        .attr("font-size", "12px")
                        .attr("fill", "#333")
                        .attr("text-anchor", "middle")
                        .attr("dy", 1)
                        .text(d => d.label);

                    simulation.on("tick", function () {{
                        link
                            .attr("x1", d => d.source.x)
                            .attr("y1", d => d.source.y)
                            .attr("x2", d => d.target.x)
                            .attr("y2", d => d.target.y);

                        node
                            .attr("x", d => d.x - 20)
                            .attr("y", d => d.y - 20);

                        labels
                            .attr("x", d => d.x)
                            .attr("y", d => d.y + 35);
                    }});

                    function dragStarted(event, d) {{
                        if (!event.active) simulation.alphaTarget(0.3).restart();
                        d.fx = d.x;
                        d.fy = d.y;
                    }}

                    function dragged(event, d) {{
                        d.fx = event.x;
                        d.fy = event.y;
                    }}

                    function dragEnded(event, d) {{
                        if (!event.active) simulation.alphaTarget(0);
                        d.fx = null;
                        d.fy = null;

                        if (d.id !== "pentester") {{
                            const csrfToken = getCookie("csrftoken");
                            fetch("{save_url_base}/" + d.id + "/", {{
                                method: "POST",
                                headers: {{
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "X-CSRFToken": csrfToken
                                }},
                                body: `x=${{d.x}}&y=${{d.y}}`
                            }}).then(r => console.log("💾 Posición guardada", r));
                        }}
                    }}

                    function getCookie(name) {{
                        let cookieValue = null;
                        if (document.cookie && document.cookie !== "") {{
                            const cookies = document.cookie.split(";");
                            for (let i = 0; i < cookies.length; i++) {{
                                const cookie = cookies[i].trim();
                                if (cookie.substring(0, name.length + 1) === (name + "=")) {{
                                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                                    break;
                                }}
                            }}
                        }}
                        return cookieValue;
                    }}
                }}

                setTimeout(updateGraph, 1500);
                document.getElementById("graphmap-tab").addEventListener("click", function () {{
                    setTimeout(updateGraph, 1000);
                }});
            }});
        </script>
        """
        return mark_safe(graphmap_html)

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
    list_display = ("name", "analisys_type", "customer_name")

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
        return HttpResponse("Aquí se manejaría la importación del archivo Nessus.")

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

