import json
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from ProjectManager.models import Project, Target, Port, Vulnerability, EvidenceImage, ReportTemplate, ReportCoverTemplate
from attack_narrative.models import Writeup

def export_project(project_id):
    """
    Exporta un proyecto y sus datos relacionados a un archivo JSON.
    """
    try:
        project = Project.objects.get(id=project_id)
    except ObjectDoesNotExist:
        return None

    project_data = {
        "name": project.name,
        "description": project.description,
        "start_date": str(project.start_date),
        "end_date": str(project.end_date),
        "language": project.language,
        "scope": project.scope,
        "report_template": project.report_template.id if project.report_template else None,
        "cover_template": project.cover_template.id if project.cover_template else None,
        "targets": [],
        "attack_narratives": [attack_narrative.id for attack_narrative in project.attack_narratives.all()]
    }

    # Exportar targets relacionados
    for target in Target.objects.filter(project=project):
        target_data = {
            "ip_address": target.ip_address,
            "fqdn": target.fqdn,
            "urlAddress": target.urlAddress,
            "os": target.os,
            "owned": target.owned,
            "jumped_from": target.jumped_from.id if target.jumped_from else None,
            "ports": []
        }

        # Exportar puertos relacionados
        for port in Port.objects.filter(target=target):
            port_data = {
                "port_number": port.port_number,
                "protocol": port.protocol,
                "state": port.state,
                "service_name": port.service_name,
                "product": port.product,
                "version": port.version,
                "banner": port.banner,
                "vulnerabilities": [vuln.id for vuln in port.vulnerabilities.all()]
            }
            target_data["ports"].append(port_data)

        project_data["targets"].append(target_data)

    # Guardar datos en un archivo JSON
    file_name = f"project_export_{project_id}.json"
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(project_data, f, indent=4, cls=DjangoJSONEncoder)

    return file_name


def import_project(json_file):
    """
    Importa un proyecto desde un archivo JSON y lo guarda en la base de datos.
    """
    with open(json_file, "r", encoding="utf-8") as f:
        project_data = json.load(f)

    # Crear nuevo proyecto
    project = Project.objects.create(
        name=project_data["name"],
        description=project_data["description"],
        start_date=project_data["start_date"],
        end_date=project_data["end_date"],
        language=project_data["language"],
        scope=project_data["scope"],
        report_template=ReportTemplate.objects.filter(id=project_data["report_template"]).first(),
        cover_template=ReportCoverTemplate.objects.filter(id=project_data["cover_template"]).first()
    )

    # Restaurar attack_narratives
    for attack_narrative_id in project_data["attack_narratives"]:
        attack_narrative = Writeup.objects.filter(id=attack_narrative_id).first()
        if attack_narrative:
            project.attack_narratives.add(attack_narrative)

    # Restaurar targets y puertos
    for target_data in project_data["targets"]:
        target = Target.objects.create(
            project=project,
            ip_address=target_data["ip_address"],
            fqdn=target_data["fqdn"],
            urlAddress=target_data["urlAddress"],
            os=target_data["os"],
            owned=target_data["owned"],
            jumped_from=Target.objects.filter(id=target_data["jumped_from"]).first() if target_data["jumped_from"] else None
        )

        # Restaurar puertos
        for port_data in target_data["ports"]:
            port = Port.objects.create(
                target=target,
                port_number=port_data["port_number"],
                protocol=port_data["protocol"],
                state=port_data["state"],
                service_name=port_data["service_name"],
                product=port_data["product"],
                version=port_data["version"],
                banner=port_data["banner"]
            )

            # Restaurar vulnerabilidades
            for vuln_id in port_data["vulnerabilities"]:
                vuln = Vulnerability.objects.filter(id=vuln_id).first()
                if vuln:
                    port.vulnerabilities.add(vuln)

    return project.id