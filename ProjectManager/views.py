# Importaciones de Python estándar
import os
import io
import re
import base64
import logging
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse
from collections import defaultdict
import xml.etree.ElementTree as ET
from io import BytesIO
import subprocess

# Importaciones de terceros
from deep_translator import GoogleTranslator
from googletrans import Translator
from PIL import Image
from bs4 import BeautifulSoup
from html2docx import html2docx

# Importaciones de Django
from django.shortcuts import render, get_object_or_404, redirect
from django.views import View
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.db import transaction
from django.db.models import Case, When, Value, IntegerField
from django.conf import settings
from django.urls import reverse
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.contrib.auth import login
from django.core.exceptions import MultipleObjectsReturned

# Importaciones de modelos y formularios de la aplicación actual
from .models import Project, Vulnerability, Port, EvidenceImage, PortVulnerabilityProject, Target, ReportTemplate
from .forms import (
    ProjectForm, NessusFileUploadForm, NmapFileUploadForm, ChangeProjectForm,
    PortVulnerabilityProjectForm, NetsparkerFileUploadForm, BurpUploadForm,
    AssignTargetsAndPortsForm, VulnerabilityForm, EvidenceImageForm, 
    ReportTemplateForm, TinyMCEForm, CustomUserCreationForm
)

# Importaciones de python-docx
from docx import Document
from docx.shared import Inches, RGBColor, Cm, Pt
from docx.oxml import parse_xml, OxmlElement, ns
from docx.oxml.ns import nsdecls
from docx.oxml.shared import qn
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX, WD_PARAGRAPH_ALIGNMENT
from docx.enum.section import WD_SECTION
from docx.oxml import OxmlElement

# Importaciones de HTML
from html.parser import HTMLParser
from .forms import ReportCoverForm
from .models import ReportCoverTemplate





logger = logging.getLogger(__name__)




#Content split to translate the whole content:
def split_and_translate(text, lang='es'):
    from googletrans import Translator
    translator = Translator()
    max_length = 4000
    chunks = [text[i:i + max_length] for i in range(0, len(text), max_length)]
    translated_text = ''
    for chunk in chunks:
        translated_chunk = translator.translate(chunk, dest=lang).text
        translated_text += translated_chunk
    return translated_text

def clean_html(raw_html):
    """Función para limpiar texto HTML de tags."""
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    return cleantext



def create_or_edit_project(request, project_id=None):
    project = None
    if project_id:
        project = get_object_or_404(Project, id=project_id)

    if request.method == 'POST':
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            return redirect('project_list')  # Redirige a la vista que prefieras
    else:
        form = ProjectForm(instance=project)

    return render(request, 'projectmanager/project_form.html', {'form': form})


# Vista para crear proyectos
def create_project(request):
    if request.method == 'POST':
        project_form = ProjectForm(request.POST)
        if project_form.is_valid():
            project = project_form.save(commit=False)
            project.report_template = project_form.cleaned_data['report_template']
            project.save()
            return redirect('project_list')
    else:
        project_form = ProjectForm()

    return render(request, 'projectmanager/create_project.html', {'project_form': project_form})


# Vista para listar todos los proyectos
def project_list(request):
    projects = Project.objects.all()
    return render(request, 'projectmanager/project_list.html', {'projects': projects})

# Vista para detalles de un proyecto específico
def project_detail(request, pk):
    # Obtener el proyecto actual
    project = get_object_or_404(Project, pk=pk)

    # Obtener vulnerabilidades relacionadas con el proyecto y agruparlas por nombre
    vulnerabilities = Vulnerability.objects.filter(project=project)
    grouped_vulnerabilities = defaultdict(list)

    # Agrupar vulnerabilidades por su nombre
    for vulnerability in vulnerabilities:
        grouped_vulnerabilities[vulnerability.name].append(vulnerability)

    # Si la solicitud es POST, se genera el reporte en formato Word
    if request.method == 'POST':
        language = request.POST.get('language', 'EN')

        # Crear el documento Word
        doc = Document()
        doc.add_heading(project.name, 0)

        # Iterar sobre las vulnerabilidades agrupadas
        for vulnerability_name, vulnerability_list in grouped_vulnerabilities.items():
            doc.add_heading(f'Vulnerability: {vulnerability_name}', level=1)

            for vulnerability in vulnerability_list:
                table = doc.add_table(rows=1, cols=2)
                table.style = 'TableGrid'

                hdr_cells = table.rows[0].cells
                hdr_cells[0].text = 'Field'
                hdr_cells[1].text = 'Detail'

                # Traducción de descripción y solución según el idioma
                description_translation = vulnerability.description_es if language == 'ES' else vulnerability.description
                solution_translation = vulnerability.solution_es if language == 'ES' else vulnerability.solution

                # Datos para la tabla
                data = [
                    ('Detail', vulnerability.name),
                    ('Solution', solution_translation),
                    ('Hosts Affected', vulnerability.hosts_affected if vulnerability.hosts_affected else 'Unknown'),
                    ('Description', description_translation),
                ]

                # Agregar filas a la tabla en el documento Word
                for label, value in data:
                    row_cells = table.add_row().cells
                    row_cells[0].text = label
                    row_cells[1].text = str(value)

        # Respuesta HTTP para descargar el documento Word
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
        response['Content-Disposition'] = f'attachment; filename="{project.name}_report.docx"'
        doc.save(response)
        return response

    # Si la solicitud es GET, renderiza la plantilla con el contexto adecuado
    return render(request, 'projectmanager/project_detail.html', {
        'project': project,
        'grouped_vulnerabilities': grouped_vulnerabilities,
    })




# Vista para importar archivo Nessus
def import_nessus_file(request, pk):
    project = get_object_or_404(Project, pk=pk)
    
    if request.method == 'POST':
        form = NessusFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            nessus_file = request.FILES['nessus_file']
            tree = ET.parse(nessus_file)
            root = tree.getroot()

            for report_host in root.findall('.//ReportHost'):
                host_ip = 'N/A'
                host_fqdn = 'N/A'
                for tag in report_host.findall('.//tag'):
                    if tag.get('name') == 'host-ip':
                        host_ip = tag.text
                    elif tag.get('name') == 'host-fqdn':
                        host_fqdn = tag.text
                
                for report_item in report_host.findall('.//ReportItem'):
                    name = report_item.get('pluginName')
                    description = report_item.findtext('description') or 'N/A'
                    solution = report_item.findtext('solution') or 'N/A'
                    see_also = report_item.findtext('see_also') or 'N/A'
                    evidence = report_item.findtext('plugin_output') or 'N/A'
                    risk_factor = report_item.findtext('risk_factor') or 'N/A'
                    cvss_temporal_score_text = report_item.findtext('cvss_temporal_score')
                    try:
                        cvss_temporal_score = Decimal(cvss_temporal_score_text) if cvss_temporal_score_text else None
                    except InvalidOperation:
                        cvss_temporal_score = None
                    port_text = report_item.get('port')
                    port_number = int(port_text) if port_text and port_text.isdigit() else 0

                    port, created = Port.objects.get_or_create(port_number=port_number, protocol='TCP')

                    # Aquí cambia Host por Target
                    target, created = Target.objects.get_or_create(ip_address=host_ip, fqdn=host_fqdn, project=project)
                    
                    vulnerability = Vulnerability.objects.create(
                        project=project,
                        name=name,
                        description=description,
                        solution=solution,
                        cvss_temporal_score=cvss_temporal_score,
                        see_also=see_also,
                        evidence=evidence,
                        risk_factor=risk_factor,
                        hosts_affected=f"{host_ip} ({host_fqdn})",
                        port=port  # Asignar el puerto a la vulnerabilidad
                    )
                    
                    # Crear una instancia de PortVulnerabilityProject y establecer la asociación con el proyecto
                    port_vulnerability_project = PortVulnerabilityProject.objects.create(
                        port=port,
                        vulnerability=vulnerability,
                        project=project
                    )

            return redirect('admin:ProjectManager_vulnerability_changelist')

    else:
        form = NessusFileUploadForm()

    return render(request, 'admin/import_nessus.html', {'form': form, 'project': project})



class AssignTargetsAndPortsView(View):
    form_class = AssignTargetsAndPortsForm
    template_name = 'admin/assign_targets_and_ports.html'

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            # Aquí manejas la lógica de guardado, por ejemplo:
            form.save()
            messages.success(request, 'Targets y Puertos asignados correctamente.')
            return redirect('alguna_url_después_de_guardar')  # Asegúrate de reemplazar esto con una URL válida
        else:
            messages.error(request, 'Por favor, corrija los errores en el formulario.')
        return render(request, self.template_name, {'form': form})



def project_hosts(request, pk):
    try:
        project = Project.objects.get(pk=pk)
    except Project.DoesNotExist:
        return render(request, 'error.html', {'message': 'El proyecto no existe'})

    hosts = Host.objects.filter(project=project)
    return render(request, 'project_hosts.html', {'project': project, 'hosts': hosts})

def targets_view(request):
    # Obtener todos los proyectos disponibles para mostrar en el formulario
    projects = Project.objects.all()

    # Filtrar los hosts disponibles en función del proyecto seleccionado en el formulario
    if request.method == 'POST':
        project_id = request.POST.get('project')
        if project_id:
            project = Project.objects.get(pk=project_id)
            hosts = Host.objects.filter(project=project)
        else:
            # Si no se selecciona ningún proyecto, mostrar todos los hosts
            hosts = Host.objects.all()
    else:
        # Si no hay datos enviados por el formulario, mostrar todos los hosts
        hosts = Host.objects.all()

    return render(request, 'targets.html', {'hosts': hosts, 'projects': projects})


#Nmap Parsers
# Asegúrate de que la función acepte el argumento 'pk'
def import_nmap_recon_file(request, pk):
    project = get_object_or_404(Project, pk=pk)
    form = NmapFileUploadForm()  # Inicializa el formulario aquí
    if request.method == 'POST':
        form = NmapFileUploadForm(request.POST, request.FILES)  # Re-inicializa el formulario con los datos enviados
        if form.is_valid():
            nmap_file = request.FILES['nmap_file']
            tree = ET.parse(nmap_file)
            root = tree.getroot()

            for host in root.findall('host'):
                status = host.find('status').get('state')
                if status == 'up':
                    ip_address = host.find("address[@addrtype='ipv4']").get('addr')
                    fqdn_element = host.find("hostnames/hostname[@type='PTR']")
                    fqdn = fqdn_element.get('name', '') if fqdn_element is not None else ''
                    # Crear o actualizar el Target
                    Target.objects.update_or_create(
                        project=project,
                        ip_address=ip_address,
                        defaults={'fqdn': fqdn}
                    )
            # Redirecciona a otra vista una vez completado el proceso
            return redirect('admin:ProjectManager_vulnerability_changelist')

    return render(request, 'admin/import_netsparker.html', {'form': form, 'project': project})
               


# Vista para importar y procesar archivo Nmap XML de escaneo completo de puertos
def import_nmap_xml(request, pk):
    project = get_object_or_404(Project, pk=pk)
    if request.method == 'POST':
        form = NmapFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            nmap_file = request.FILES.get('nmap_file')
            tree = ET.parse(nmap_file)
            root = tree.getroot()

            for host in root.findall('.//host'):
                status = host.find('.//status').get('state')
                if status == 'up':
                    ip_address = host.find('.//address[@addrtype="ipv4"]').get('addr')
                    fqdn_elements = host.findall('.//hostname')
                    fqdn = ' / '.join(elem.get('name') for elem in fqdn_elements if elem is not None)
                    os_match = host.find('.//os/osmatch')
                    os_name = os_match.get('name') if os_match else ""

                    target, created = Target.objects.update_or_create(
                        project=project, ip_address=ip_address,
                        defaults={'fqdn': fqdn, 'os': os_name})

                    for port_element in host.findall('.//port'):
                        port_id = port_element.get('portid')
                        protocol = port_element.get('protocol')
                        state = port_element.find('.//state').get('state')
                        service_element = port_element.find('.//service')
                        service_name = service_element.get('name') if service_element else ''
                        product = service_element.get('product') if service_element else ''
                        version = service_element.get('version') if service_element else ''

                        Port.objects.update_or_create(
                            target=target, port_number=port_id, protocol=protocol,
                            defaults={'state': state, 'service_name': service_name, 'product': product, 'version': version})

            return redirect('admin:ProjectManager_vulnerability_changelist')
    else:
        form = NmapFileUploadForm()

    return render(request, 'admin/import_netsparker.html', {'form': form, 'project': project})



# Tapa
def configurar_tapa_reporte(request):
    if request.method == 'POST':
        form = ReportCoverForm(request.POST, request.FILES)
        if form.is_valid():
            # Guardar la información en el modelo correspondiente
            cover = ReportCover(
                tipo_analisis=form.cleaned_data['tipo_analisis'],
                nombre_cliente=form.cleaned_data['nombre_cliente'],
                fecha_inicio=form.cleaned_data['fecha_inicio'],
                fecha_fin=form.cleaned_data['fecha_fin'],
                imagen_proveedor=form.cleaned_data['imagen_proveedor'],
                header_imagen=form.cleaned_data['header_imagen']
            )
            cover.save()
            return redirect('reporte_generado')  # Redirigir a la vista donde se genera el reporte
    else:
        form = ReportCoverForm()

    return render(request, 'configurar_tapa_reporte.html', {'form': form})





# Vista para mostrar información del proyecto
def project_info(request, object_id):
    project = get_object_or_404(Project, pk=object_id)
    return render(request, 'admin/project_info.html', {'project': project})

# Vista para mostrar vulnerabilidades del proyecto
def project_vulnerabilities(request, object_id):
    project = get_object_or_404(Project, pk=object_id)
    return render(request, 'admin/project_vulnerabilities.html', {'project': project})

# Vista para mostrar puertos del proyecto
def project_ports(request, object_id):
    project = get_object_or_404(Project, pk=object_id)
    return render(request, 'admin/project_ports.html', {'project': project})

# Vista para cambiar los detalles de un proyecto
def change_project(request, pk):
    project = get_object_or_404(Project, pk=pk)
    if request.method == 'POST':
        form = ChangeProjectForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            return redirect('project_list')
    else:
        form = ChangeProjectForm(instance=project)

    return render(request, 'projectmanager/change_project.html', {'form': form})



# Función para traducir al español
def translate_to_spanish(text):
    # Crea una instancia del traductor de Google
    translator = google_translator()

    # Traduce el texto al español
    translated_text = translator.translate(text, lang_tgt='es')

    return translated_text
    

    
def add_vulnerability(request):
    if request.method == 'POST':
        form = VulnerabilityForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('vulnerability_list')  # Cambia 'vulnerability_list' por el nombre de tu vista de listado de vulnerabilidades
    else:
        form = VulnerabilityForm()
    return render(request, 'projectmanager/add_vulnerability.html', {'form': form})




# Función para aplicar color de fondo a las celdas de la tabla en el documento
def set_cell_background(cell, color):
    cell_properties = cell._element.get_or_add_tcPr()
    shading = OxmlElement('w:shd')
    shading.set(qn('w:fill'), color)
    cell_properties.append(shading)

def risk_factor_to_legible_text_and_color(risk_factor, language='en'):
    risk_mapping = {
        'Critical': ('Crítica', '800080') if language == 'es' else ('Critical', '800080'),  # Púrpura
        'High': ('Alto', 'FF0000') if language == 'es' else ('High', 'FF0000'),  # Rojo
        'Medium': ('Medio', 'FFA500') if language == 'es' else ('Medium', 'FFA500'),  # Naranja
        'Low': ('Bajo', '008000') if language == 'es' else ('Low', '008000'),  # Verde
    }
    return risk_mapping.get(risk_factor, ('Desconocido', '000000'))  # Valor por defecto si el riesgo es desconocido





def parse_styles(style_str):
    styles = {}
    for style in style_str.split(';'):
        if ':' in style:
            key, value = style.split(':')
            key = key.strip()
            value = value.strip()
            if key == 'color':
                styles['color'] = RGBColor.from_string(value.lstrip('#'))
            elif key == 'font-size':
                styles['font_size'] = int(value.replace('px', ''))
            elif key == 'font-weight' and value == 'bold':
                styles['bold'] = True
            elif key == 'font-style' and value == 'italic':
                styles['italic'] = True
            elif key == 'text-decoration':
                if 'underline' in value:
                    styles['underline'] = True
                if 'line-through' in value:
                    styles['strike'] = True
    return styles

def add_run_with_styles(paragraph, text, styles):
    run = paragraph.add_run(text)
    if 'bold' in styles:
        run.bold = True
    if 'italic' in styles:
        run.italic = True
    if 'underline' in styles:
        run.underline = True
    if 'strike' in styles:
        run.font.strike = True
    if 'color' in styles:
        run.font.color.rgb = styles['color']
    if 'font_size' in styles:
        run.font.size = Pt(styles['font_size'])
    return run



def generate_vulnerability_table(doc, vulnerabilities, language):
    for vulnerability_name, details in vulnerabilities.items():
        legible_risk = details['risk']
        risk_color_code = details['risk_color']

        # Crear el párrafo para el título de la vulnerabilidad con el esquema de colores adecuado
        paragraph = doc.add_paragraph(style='Heading1')
        run_risk = paragraph.add_run(f"{legible_risk} - ")
        run_risk.font.color.rgb = RGBColor(int(risk_color_code[0:2], 16), int(risk_color_code[2:4], 16), int(risk_color_code[4:], 16))
        run_risk.bold = True

        run_name = paragraph.add_run(vulnerability_name)
        run_name.bold = True

        # Definir los títulos de las columnas según el idioma seleccionado
        if language == 'es':
            titles = ['Hosts Afectados', 'Puerto', 'Descripción', 'Solución', 'Evidencia', 'Evidencia Adicional']
        else:
            titles = ['Affected Hosts', 'Ports', 'Description', 'Solution', 'Evidence', 'Extra Evidence']

        # Crear la tabla para los detalles de la vulnerabilidad
        table = doc.add_table(rows=6, cols=2)
        table.style = 'TableGrid'
        table.autofit = True

        # Establecer el ancho de las columnas
        column_width_left = Cm(2.5)
        column_width_right = Cm(15)
        table.columns[0].width = column_width_left
        table.columns[1].width = column_width_right

        details_data = [
            ', '.join(details['hosts']) if 'hosts' in details else 'Unknown',
            ', '.join(str(port) for port in details['ports']) if 'ports' in details else 'Unknown',
            details['description'] if 'description' in details else '',
            details['solution'] if 'solution' in details else '',
            ', '.join(details['evidence']) if 'evidence' in details else 'Unknown',
            '',  # Placeholder for additional evidence cell
        ]

        for i, title in enumerate(titles):
            cell_left = table.cell(i, 0)
            cell_right = table.cell(i, 1)

            # Aplicar formato al encabezado y la columna izquierda
            cell_left.text = title
            cell_left.paragraphs[0].runs[0].bold = True
            cell_left.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # Blanco
            set_cell_background(cell_left, '000000')  # Negro

            cell_right.text = details_data[i]

            # Aplicar color de fondo según la criticidad para la columna derecha
            set_cell_background(cell_right, risk_color_code)
            for paragraph in cell_right.paragraphs:
                for run in paragraph.runs:
                    run.font.color.rgb = RGBColor(255, 255, 255)  # Blanco

        # Añadir la imagen de la evidencia adicional si está disponible
        extra_evidence_image_cell = table.cell(5, 1)
        evidence_images = EvidenceImage.objects.filter(vulnerability__name=vulnerability_name)
        for evidence_image in evidence_images:
            image_path = os.path.join(settings.MEDIA_ROOT, evidence_image.image.name)
            if os.path.exists(image_path):
                run = extra_evidence_image_cell.add_paragraph().add_run()
                run.add_picture(image_path, width=Cm(10))  # Ajustar el ancho según sea necesario



def handle_element(element, parent, doc, vulnerabilities, language):
    if isinstance(element, str):
        if element.strip():
            parent.add_run(element.strip())
        return

    if element.name == 'p':
        paragraph = doc.add_paragraph()
        text = element.get_text()
        if '###BreakPage###' in text:
            doc.add_page_break()
            text = text.replace('###BreakPage###', '')  # Remove the marker
        if '###VulnsTable###' in text:
            text = text.replace('###VulnsTable###', '')
            add_run_with_styles(paragraph, text.strip(), parse_styles(element.get('style', '')))
            generate_vulns_summary_table(doc, vulnerabilities, language)
        else:
            if 'style' in element.attrs:
                styles = parse_styles(element['style'])
                add_run_with_styles(paragraph, text.strip(), styles)
            else:
                for child in element.children:
                    handle_element(child, paragraph, doc, vulnerabilities, language)
    elif element.name in ['ul', 'ol']:
        list_type = 'ListBullet' if element.name == 'ul' else 'ListNumber'
        for li in element.find_all('li'):
            paragraph = doc.add_paragraph(style=list_type)
            if 'style' in li.attrs:
                styles = parse_styles(li['style'])
                add_run_with_styles(paragraph, li.get_text(strip=True), styles)
            else:
                paragraph.add_run(li.get_text(strip=True))
    elif element.name in ['h1', 'h2', 'h3']:
        level = int(element.name[1])
        paragraph = doc.add_heading(level=level)
        if 'style' in element.attrs:
            styles = parse_styles(element['style'])
            add_run_with_styles(paragraph, element.get_text(strip=True), styles)
        else:
            for child in element.children:
                handle_element(child, paragraph, doc, vulnerabilities, language)
    elif element.name == 'img':
        src = element['src']
        if src.startswith('data:image'):
            format, imgstr = src.split(';base64,')
            ext = format.split('/')[-1]
            add_base64_image_to_doc(doc, imgstr, ext)
    elif element.name == 'span' and 'style' in element.attrs:
        color_code = element['style'].split('color:')[1].split(';')[0].strip()
        rgb = RGBColor.from_string(color_code.replace('#', ''))
        run = parent.add_run(element.get_text(strip=True))
        run.font.color.rgb = rgb
    elif element.name == 'hr':
        paragraph = doc.add_paragraph()
        run = paragraph.add_run()
        pBdr = OxmlElement('w:pBdr')
        bottom = OxmlElement('w:bottom')
        bottom.set(qn('w:val'), 'single')
        bottom.set(qn('w:sz'), '6')
        bottom.set(qn('w:space'), '1')
        bottom.set(qn('w:color'), 'auto')
        pBdr.append(bottom)
        paragraph._element.get_or_add_pPr().append(pBdr)
    elif element.name == 'br':
        parent.add_run().add_break()
    else:
        for child in element.children:
            handle_element(child, parent, doc, vulnerabilities, language)

def add_html_to_doc(doc, html_content, vulnerabilities, language):
    soup = BeautifulSoup(html_content, 'html.parser')
    for element in soup.children:
        if isinstance(element, str):
            continue
        handle_element(element, doc, doc, vulnerabilities, language)




def consolidate_vulnerabilities(vulnerabilities):
    consolidated = {}
    for vuln in vulnerabilities:
        if vuln.name not in consolidated:
            consolidated[vuln.name] = vuln.risk_factor
        else:
            # Mantener la mayor severidad si hay duplicados
            current_risk = consolidated[vuln.name]
            if risk_factor_to_int(vuln.risk_factor) < risk_factor_to_int(current_risk):
                consolidated[vuln.name] = vuln.risk_factor
    return consolidated

def risk_factor_to_int(risk_factor):
    risk_mapping = {
        'Critical': 1,
        'High': 2,
        'Medium': 3,
        'Low': 4
    }
    return risk_mapping.get(risk_factor, 5)




def add_hyperlink(paragraph, text, url):
    """
    A function that places a hyperlink within a paragraph object.
    :param paragraph: The paragraph we are adding the hyperlink to.
    :param text: The text displayed for the hyperlink.
    :param url: A string containing the required url
    :return: The hyperlink object
    """
    # This gets access to the document.xml.rels file and gets a new relation id value
    part = paragraph.part
    r_id = part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True)

    # Create the w:hyperlink tag and add needed values
    hyperlink = OxmlElement('w:hyperlink')
    hyperlink.set(qn('r:id'), r_id)

    # Create a w:r element and a new w:rPr element
    new_run = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    new_run.append(rPr)

    # Create a w:t element with the text
    w_t = OxmlElement('w:t')
    w_t.text = text

    # Add the w:t element to the w:r element
    new_run.append(w_t)

    # Add the w:r element to the w:hyperlink element
    hyperlink.append(new_run)

    # Add the w:hyperlink element to the paragraph
    paragraph._p.append(hyperlink)

    return hyperlink

def generate_vulnerability_table(doc, vulnerabilities, language='en'):
    if language == 'es':
        headers = ['Vulnerabilidad', 'Severidad']
    else:
        headers = ['Vulnerability', 'Severity']

    table = doc.add_table(rows=1, cols=2)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = headers[0]
    hdr_cells[1].text = headers[1]

    for cell in hdr_cells:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.bold = True

    table.columns[0].width = Inches(4.6)
    table.columns[1].width = Inches(1.2)

    consolidated_vulns = consolidate_vulnerabilities(vulnerabilities)
    sorted_vulns = sorted(consolidated_vulns.items(), key=lambda item: risk_factor_to_int(item[1]))

    for vuln, risk in sorted_vulns:
        row_cells = table.add_row().cells
        add_hyperlink(row_cells[0].paragraphs[0], vuln, f'#{vuln}')
        
        if not row_cells[0].paragraphs[0].runs:
            row_cells[0].paragraphs[0].add_run()
        row_cells[0].paragraphs[0].runs[0].font.bold = True

        run = row_cells[1].paragraphs[0].add_run(risk)
        run.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)
        
        if risk == 'Critical':
            set_cell_background(row_cells[1], '800080')
        elif risk == 'High':
            set_cell_background(row_cells[1], 'FF0000')
        elif risk == 'Medium':
            set_cell_background(row_cells[1], 'FFA500')
        elif risk == 'Low':
            set_cell_background(row_cells[1], '008000')



def generate_vulns_summary_table(doc, vulnerabilities, language):
    # Ordenar las vulnerabilidades por nivel de criticidad
    criticity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: criticity_order.get(x.risk_factor, 4))

    table = doc.add_table(rows=len(sorted_vulnerabilities) + 1, cols=2)
    table.style = 'TableGrid'
    
    # Encabezados
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Vulnerabilidad' if language == 'es' else 'Vulnerability'
    hdr_cells[1].text = 'Severidad' if language == 'es' else 'Severity'
    for hdr_cell in hdr_cells:
        hdr_cell.paragraphs[0].runs[0].bold = True
        hdr_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # Blanco
        set_cell_background(hdr_cell, '000000')  # Negro

    # Datos de vulnerabilidades
    for idx, vuln in enumerate(sorted_vulnerabilities, start=1):
        row_cells = table.rows[idx].cells
        row_cells[0].text = vuln.name
        legible_risk, risk_color_code = risk_factor_to_legible_text_and_color(vuln.risk_factor, language)
        
        severity_paragraph = row_cells[1].paragraphs[0]
        severity_run = severity_paragraph.add_run(legible_risk)
        severity_run.bold = True

        set_cell_background(row_cells[1], risk_color_code)
        for paragraph in row_cells[1].paragraphs:
            for run in paragraph.runs:
                run.font.color.rgb = RGBColor(255, 255, 255)  # Blanco



def set_cell_styles(cell, styles):
    if 'color' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.color.rgb = styles['color']
    if 'font_size' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.size = Pt(styles['font_size'])
    if 'bold' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.bold = styles['bold']
    if 'italic' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.italic = styles['italic']
    if 'underline' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.underline = styles['underline']
    if 'strike' in styles:
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.strike = styles['strike']

def add_base64_image_to_doc(doc, base64_str, ext):
    decoded_img = base64.b64decode(base64_str)
    img_io = io.BytesIO(decoded_img)
    img_io.seek(0)
    
    # Obtener el ancho de la página y ajustar el ancho de la imagen
    section = doc.sections[0]
    page_width = section.page_width - section.left_margin - section.right_margin
    doc.add_picture(img_io, width=page_width)
    img_io.close()





def generate_report(request, project_id):
    if request.method == 'POST':
        language = request.POST.get('language', 'en').lower()
        project = get_object_or_404(Project, pk=project_id)

        # Crear el documento
        doc = Document()

        # --- Sección de la Tapa del Reporte ---
        cover = project.cover_template
        if cover:
            # Título utilizando el nombre del proyecto
            title = doc.add_heading(level=1)
            title_run = title.add_run(f"Pruebas de Seguridad Ofensiva: {cover.tipo_analisis} - {project.name}")
            title_run.font.size = Pt(24)  # Tamaño de 24 pt
            title_run.bold = True  # Negrita
            title.alignment = 1  # Centrar el título

            # Añadir el texto "| REPORTE EJECUTIVO/TÉCNICO |"
            report_type_paragraph = doc.add_paragraph()
            report_type_run = report_type_paragraph.add_run("| REPORTE EJECUTIVO/TÉCNICO |")
            report_type_run.bold = True  # Negrita
            report_type_run.font.size = Pt(15.5)  # Tamaño de 15.5 pt
            report_type_run.font.color.rgb = RGBColor(255, 140, 0)  # Color naranja
            report_type_paragraph.alignment = 1  # Centrar el texto

            # Fechas del compromiso
            fecha_inicio = project.start_date.strftime("%d/%m/%Y")
            fecha_fin = project.end_date.strftime("%d/%m/%Y")
            fechas_texto = f"Fecha de inicio del compromiso: {fecha_inicio} / Fecha de finalización del compromiso: {fecha_fin}"
            fecha_paragraph = doc.add_paragraph(fechas_texto)
            fecha_paragraph.alignment = 1  # Centrar las fechas
            fecha_run = fecha_paragraph.runs[0]
            fecha_run.font.size = Pt(8)  # Tamaño de 8 pt

            # Imagen del proveedor (alineada al borde izquierdo y ajustada al ancho)
            if cover.imagen_proveedor:
                paragraph = doc.add_paragraph()
                paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT  # Asegurar que el párrafo esté alineado a la izquierda
                run = paragraph.add_run()
                run.add_picture(cover.imagen_proveedor.path, width=Inches(8.5))  # Ancho de 8.5 pulgadas

            # Imagen del header (colocada en la esquina superior izquierda)
            if cover.header_imagen:
                header = doc.sections[0].header
                header_paragraph = header.paragraphs[0]
                header_run = header_paragraph.add_run()
                header_run.add_picture(cover.header_imagen.path, width=Inches(0.9))  # Ajustar ancho según sea necesario
            doc.add_page_break()

            # Imagen del cliente (header a la derecha)
            if cover.customer_header_image:
                header = doc.sections[0].header
                header_paragraph = header.add_paragraph()
                header_paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT  # Alinear a la derecha
                header_run = header_paragraph.add_run()
                header_run.add_picture(cover.customer_header_image.path, width=Inches(0.9))  # Ajustar ancho según sea necesario

        else:
            doc.add_paragraph("No se seleccionó una tapa para este reporte.")
        # --- Fin de la Sección de la Tapa del Reporte ---

        # Ejecutar el script de Puppeteer para capturar el gráfico
        subprocess.run(["node", "scripts/capture_graph.js"], check=True)

        # Obtener el contenido del reporte
        report_content = project.report_template.content if project.report_template else ''

        # Generar o cargar la imagen del gráfico
        graph_image_path = '/static/images/graph.png'  # La ruta de la imagen generada
        graph_image_tag = f'<img src="{graph_image_path}" alt="Graph Map">'

        # Reemplaza el tag ###GrapMap### con la imagen del gráfico
        report_content = report_content.replace('###GrapMap###', graph_image_tag)

        # Insertar tabla de contenido
        toc_paragraph = doc.add_paragraph()
        toc_run = toc_paragraph.add_run("Table of Contents")
        toc_run.bold = True

        toc = doc.add_paragraph()
        run = toc.add_run()
        fldChar = OxmlElement('w:fldChar')
        fldChar.set(qn('w:fldCharType'), 'begin')
        instrText = OxmlElement('w:instrText')
        instrText.text = 'TOC \\o "1-3" \\h \\z \\u'
        fldChar2 = OxmlElement('w:fldChar')
        fldChar2.set(qn('w:fldCharType'), 'separate')
        fldChar3 = OxmlElement('w:fldChar')
        fldChar3.set(qn('w:fldCharType'), 'end')
        run._r.append(fldChar)
        run._r.append(instrText)
        run._r.append(fldChar2)
        run._r.append(fldChar3)

        doc.add_page_break()

        doc.add_heading(project.name, 0)

        # Obtener todas las vulnerabilidades del proyecto y ordenarlas por criticidad
        vulnerabilities = list(Vulnerability.objects.filter(project=project).order_by('-risk_factor'))

        # Procesar el contenido del Report Template
        if report_content:
            add_html_to_doc(doc, report_content, vulnerabilities, language)

        # Reemplazar ###Scope### por el contenido del campo scope con formato
        for para in doc.paragraphs:
            if '###Scope###' in para.text:
                scope_data = project.scope.split('\n') if project.scope else []
                if scope_data:
                    # Dividir los datos del alcance en 3 columnas
                    num_rows = (len(scope_data) + 2) // 3
                    table = doc.add_table(rows=num_rows + 1, cols=3)
                    table.style = 'TableGrid'

                    # Añadir el encabezado
                    hdr_cells = table.rows[0].cells
                    for hdr_cell in hdr_cells:
                        hdr_cell.text = 'Scope' if language == 'en' else 'Alcance'
                        hdr_cell.paragraphs[0].runs[0].bold = True
                        hdr_cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)  # Blanco
                        set_cell_background(hdr_cell, '000000')  # Negro

                    # Añadir los datos del alcance distribuidos en 3 columnas
                    for idx, scope in enumerate(scope_data):
                        col = idx // num_rows
                        row = idx % num_rows + 1
                        cell = table.cell(row, col)
                        cell.text = scope.strip()
                        # Aplicar color de fondo alterno
                        if row % 2 == 0:
                            set_cell_background(cell, 'D3D3D3')  # Gris claro
                        else:
                            set_cell_background(cell, 'FFFFFF')  # Blanco

                    # Insertar la tabla en la ubicación del marcador
                    para._element.addnext(table._element)
                para.text = para.text.replace('###Scope###', '')

        # Dictionary para almacenar vulnerabilidades consolidadas
        consolidated_vulnerabilities = {}

        # Definir el orden de criticidad
        criticity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

        # Ordenar las vulnerabilidades por nivel de criticidad
        vulnerabilities = sorted(vulnerabilities, key=lambda x: criticity_order.get(x.risk_factor, 4))

        # Generar el contenido de las vulnerabilidades y recopilar títulos y subtítulos
        for vulnerability in vulnerabilities:
            legible_risk, risk_color_code = risk_factor_to_legible_text_and_color(vulnerability.risk_factor, language)
            vulnerability_name = vulnerability.name

            # Si la vulnerabilidad ya está procesada, actualizar sus detalles
            if vulnerability_name in consolidated_vulnerabilities:
                consolidated_vulnerabilities[vulnerability_name]['hosts'].append(vulnerability.hosts_affected)
                consolidated_vulnerabilities[vulnerability_name]['ports'].append(vulnerability.port)
                consolidated_vulnerabilities[vulnerability_name]['evidence'].extend(vulnerability.evidence.split(','))  # Split the evidence string
            else:
                consolidated_vulnerabilities[vulnerability_name] = {
                    'risk': legible_risk,
                    'risk_color': risk_color_code,
                    'hosts': [vulnerability.hosts_affected],
                    'ports': [vulnerability.port],
                    'description': vulnerability.description_es if language == 'es' else vulnerability.description,
                    'solution': vulnerability.solution_es if language == 'es' else vulnerability.solution,
                    'evidence': vulnerability.evidence.split(','),  # Split the evidence string
                }

        # Insertar la tabla de resumen de vulnerabilidades
        overall_table_marker = '###OverallTableVulns###'
        for para in doc.paragraphs:
            if overall_table_marker in para.text:
                para.text = ""  # Limpia el marcador
                # Insertar la tabla en el lugar del marcador
                table = doc.add_table(rows=2, cols=4)
                table.style = 'TableGrid'
                table.autofit = True

                # Establecer el ancho de las columnas
                column_width = Cm(4)
                for col in table.columns:
                    col.width = column_width

                # Rellenar la tabla con los valores
                header_cells = ['Crítica' if language == 'es' else 'Critical',
                                'Alta' if language == 'es' else 'High',
                                'Media' if language == 'es' else 'Medium',
                                'Baja' if language == 'es' else 'Low']
                
                risk_factors = ['Critical', 'High', 'Medium', 'Low']
                counts = [sum(1 for v in vulnerabilities if v.risk_factor == risk) for risk in risk_factors]

                for i, (header, count, risk) in enumerate(zip(header_cells, counts, risk_factors)):
                    legible_risk, risk_color_code = risk_factor_to_legible_text_and_color(risk, language)
                    color = RGBColor(255, 255, 255)  # Blanco

                    table.cell(0, i).text = header
                    table.cell(1, i).text = str(count)

                    set_cell_background(table.cell(0, i), risk_color_code)
                    set_cell_background(table.cell(1, i), risk_color_code)
                    
                    for row in range(2):
                        cell = table.cell(row, i)
                        for paragraph in cell.paragraphs:
                            for run in paragraph.runs:
                                run.bold = True
                                run.font.color.rgb = color

                para._element.addnext(table._element)

        # Generar las tablas de vulnerabilidades
        for vulnerability_name, details in consolidated_vulnerabilities.items():
            legible_risk = details['risk']
            risk_color_code = details['risk_color']

            # Crear el párrafo para el título de la vulnerabilidad con el esquema de colores adecuado
            paragraph = doc.add_paragraph(style='Heading1')
            run_risk = paragraph.add_run(f"{legible_risk} - ")
            run_risk.font.color.rgb = RGBColor(int(risk_color_code[0:2], 16), int(risk_color_code[2:4], 16), int(risk_color_code[4:], 16))
            run_risk.bold = True

            run_name = paragraph.add_run(vulnerability_name)
            run_name.bold = True

            # Definir los títulos de las columnas según el idioma seleccionado
            if language == 'es':
                titles = ['Hosts Afectados', 'Puerto', 'Descripción', 'Solución', 'Evidencia', 'Evidencia Adicional']
            else:
                titles = ['Affected Hosts', 'Ports', 'Description', 'Solution', 'Evidence', 'Extra Evidence']

            # Crear la tabla para los detalles de la vulnerabilidad
            table = doc.add_table(rows=6, cols=2)
            table.style = 'TableGrid'
            table.autofit = True

            # Establecer el ancho de las columnas
            column_width_left = Cm(2.5)
            column_width_right = Cm(15)
            table.columns[0].width = column_width_left
            table.columns[1].width = column_width_right

            details_data = [
                ', '.join(details['hosts']) if 'hosts' in details else 'Unknown',
                ', '.join(str(port) for port in details['ports']) if 'ports' in details else 'Unknown',
                details['description'] if 'description' in details else '',
                details['solution'] if 'solution' in details else '',
                ', '.join(details['evidence']) if 'evidence' in details else 'Unknown',
                '',  # Placeholder for additional evidence cell
            ]

            for i, title in enumerate(titles):
                cell = table.cell(i, 0)
                cell_text = cell.paragraphs[0].add_run(title)
                cell_text.bold = True

                table.cell(i, 1).text = details_data[i]

                # Aplicar el color de fondo según la criticidad
                set_cell_background(cell, risk_color_code)
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.color.rgb = RGBColor(255, 255, 255)  # Blanco

            # Añadir la imagen de la evidencia adicional si está disponible
            extra_evidence_image_cell = table.cell(5, 1)
            evidence_images = EvidenceImage.objects.filter(vulnerability__name=vulnerability_name)
            for evidence_image in evidence_images:
                image_path = os.path.join(settings.MEDIA_ROOT, evidence_image.image.name)
                if os.path.exists(image_path):
                    run = extra_evidence_image_cell.add_paragraph().add_run()
                    run.add_picture(image_path, width=Cm(10))  # Ajustar el ancho según sea necesario

        # Procesar saltos de página
        for paragraph in doc.paragraphs:
            if '###BreakPage###' in paragraph.text:
                paragraph.text = paragraph.text.replace('###BreakPage###', '')
                doc.add_page_break()

        # Inserta un salto de página después de la tabla
        doc.add_page_break()

        # Guardar el documento en un buffer y preparar la respuesta
        buffer = io.BytesIO()
        doc.save(buffer)
        buffer.seek(0)

        filename = f"{project.name}_report_{language}.docx"
        response = HttpResponse(buffer.getvalue(), content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    else:
        return render(request, 'projectmanager/select_report_language.html', {'project_id': project_id})








def generate_vulnerabilities_table(project, language):
    # Obtener todas las vulnerabilidades del proyecto
    vulnerabilities = Vulnerability.objects.filter(project=project)

    # Ordenar las vulnerabilidades por nivel de criticidad
    vulnerabilities = sorted(vulnerabilities, key=lambda x: risk_factor_to_numeric(x.risk_factor, language))

    # Crear la tabla HTML
    table_html = '<table border="1">'
    table_html += '<tr><th>Affected Hosts</th><th>Ports</th><th>Description</th><th>Solution</th><th>Evidence</th></tr>'

    for vulnerability in vulnerabilities:
        # Obtener los detalles de la vulnerabilidad
        hosts_affected = vulnerability.hosts_affected if vulnerability.hosts_affected else 'Unknown'
        ports = vulnerability.port if vulnerability.port else 'Unknown'
        description = vulnerability.description_es if language == 'es' else vulnerability.description
        solution = vulnerability.solution_es if language == 'es' else vulnerability.solution
        evidence = vulnerability.evidence if vulnerability.evidence else 'Unknown'

        # Agregar una fila a la tabla
        table_html += f'<tr><td>{hosts_affected}</td><td>{ports}</td><td>{description}</td><td>{solution}</td><td>{evidence}</td></tr>'

    table_html += '</table>'
    
    return table_html


def apply_styles(paragraph, element):
    """
    Aplica estilos a un párrafo de acuerdo con los estilos definidos en un elemento HTML.
    
    Parameters:
    - paragraph: El objeto Paragraph de python-docx al que se aplicarán los estilos.
    - element: El elemento HTML que contiene los estilos a aplicar.
    """
    # Verifica si hay un estilo de color definido en el elemento HTML
    if 'color' in element.attrs:
        color = element.attrs['color']
        # Convierte el color hexadecimal a RGB
        rgb_color = RGBColor(*tuple(int(color[i:i+2], 16) for i in (1, 3, 5)))
        # Aplica el color al texto del párrafo
        for run in paragraph.runs:
            run.font.color.rgb = rgb_color
    
    # Verifica si hay un estilo de tamaño de fuente definido en el elemento HTML
    if 'font-size' in element.attrs:
        font_size = element.attrs['font-size']
        # Convierte el tamaño de la fuente a puntos
        font_size_pt = Pt(int(font_size[:-2]))  # Suponiendo que el tamaño de fuente se especifica en px
        # Aplica el tamaño de la fuente al texto del párrafo
        for run in paragraph.runs:
            run.font.size = font_size_pt
    
    # Verifica si hay un estilo de alineación definido en el elemento HTML
    if 'text-align' in element.attrs:
        text_align = element.attrs['text-align']
        # Mapea la alineación HTML a la alineación de párrafo de docx
        alignment_mapping = {
            'left': WD_PARAGRAPH_ALIGNMENT.LEFT,
            'center': WD_PARAGRAPH_ALIGNMENT.CENTER,
            'right': WD_PARAGRAPH_ALIGNMENT.RIGHT,
            'justify': WD_PARAGRAPH_ALIGNMENT.JUSTIFY
        }
        # Aplica la alineación al párrafo
        paragraph.alignment = alignment_mapping.get(text_align, WD_PARAGRAPH_ALIGNMENT.LEFT)





#Area de Template para customizar el reporte:
def report_template_list(request):
    templates = ReportTemplate.objects.all()
    return render(request, 'report_template_list.html', {'templates': templates})

def report_template_create(request):
    if request.method == 'POST':
        form = ReportTemplateForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('report_template_list')
    else:
        form = ReportTemplateForm()
    return render(request, 'report_template_form.html', {'form': form})

def report_template_edit(request, pk):
    template = get_object_or_404(ReportTemplate, pk=pk)
    if request.method == 'POST':
        form = ReportTemplateForm(request.POST, instance=template)
        if form.is_valid():
            form.save()
            return redirect('report_template_list')
    else:
        form = ReportTemplateForm(instance=template)
    return render(request, 'report_template_form.html', {'form': form})

def report_template_delete(request, pk):
    template = get_object_or_404(ReportTemplate, pk=pk)
    template.delete()
    return redirect('report_template_list')

def editor_page(request):
    if request.method == 'POST':
        form = TinyMCEForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            # Procesar el formulario aquí, por ejemplo, guardar el contenido en la base de datos
            # En este ejemplo, simplemente mostramos el contenido en la consola del servidor
            print("Contenido del formulario:", content)
            return HttpResponse("Contenido guardado correctamente.")
    else:
        form = TinyMCEForm()
    return render(request, 'editor_page.html', {'form': form})





# Netsparker Parser
def import_netsparker_file(request, pk):
    project = get_object_or_404(Project, pk=pk)
    
    if request.method == 'POST':
        form = NetsparkerFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            netsparker_file = request.FILES['netsparker_file']  # Asegúrate de que netsparker_file sea un InMemoryUploadedFile
            tree = ET.parse(netsparker_file)
            root = tree.getroot()

            # Extraer y procesar la URL base del módulo <target>
            target_url = root.find('.//target/url').text if root.find('.//target/url') is not None else None

            # Verificar y actualizar/crear el Target si target_url existe
            if target_url:
                target, created = Target.objects.update_or_create(
                    project=project,
                    urlAddress=target_url,
                    defaults={}  # Añade aquí cualquier campo adicional que necesites actualizar
                )

            for vuln in root.findall('.//vulnerability'):
                vuln_url = vuln.find('url').text
                severity = vuln.find('severity').text
                title = vuln.find('title').text
                description_html = vuln.find('description').text or ""
                remedy_html = vuln.find('remedy').text or ""
                externalReferences_html = vuln.find('externalReferences').text or ""
                rawrequest = vuln.find('rawrequest').text or ""
                rawresponse = vuln.find('rawresponse').text or ""

                # Limpiar los campos HTML
                description_clean = clean_html(description_html)
                remedy_clean = clean_html(remedy_html)
                externalReferences_clean = clean_html(externalReferences_html)

                # Traducir al español
                description_es = GoogleTranslator(source='auto', target='es').translate(description_clean)
                remedy_es = GoogleTranslator(source='auto', target='es').translate(remedy_clean)

                # Construir el texto de evidencia
                evidence_text = f"Request:\n{rawrequest}\nResponse:\n{rawresponse}"

                # Actualizar o crear la vulnerabilidad con todos los datos procesados
                vulnerability, vuln_created = Vulnerability.objects.update_or_create(
                    project=project,
                    name=title,
                    defaults={
                        'description': description_clean,
                        'solution': remedy_clean,
                        'description_es': description_es,
                        'solution_es': remedy_es,
                        'risk_factor': severity,
                        'see_also': externalReferences_clean,
                        'hosts_affected': vuln_url,  # Considera manejar múltiples URLs adecuadamente
                        'evidence': evidence_text
                    }
                )

            return redirect(reverse('admin:ProjectManager_project_changelist'))
    else:
        form = NetsparkerFileUploadForm()

    return render(request, 'admin/import_file.html', {'form': form, 'project': project})



#Users register
def login_view(request):
    # Lógica de la vista de inicio de sesión
    return render(request, 'registration/login.html')

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirige a la página de inicio de sesión después de registrarse
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})



def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')  # Asume que tienes una vista 'home'
    else:
        form = CustomUserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})






#Parser Acunetix
def import_acunetix_xml(request, pk):
    project = get_object_or_404(Project, pk=pk)

    if request.method == 'POST':
        xml_file = request.FILES.get('acunetix_file')
        if xml_file:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Conjunto para almacenar hosts afectados únicos
            unique_hosts_affected = set()

            for scan in root.findall('.//Scan'):
                # Manejar StartURL y Crawler StartUrl
                start_url = scan.find('StartURL').text if scan.find('StartURL') is not None else ''
                crawler_start_url = scan.get('StartUrl', start_url)  # Usar StartURL como fallback

                os_element = scan.find('.//Os')
                if os_element is not None:
                    # Obtener el contenido del nodo <Os> como una cadena de texto
                    os_content = os_element.text.strip() if os_element.text else None
                    if os_content:
                        # Buscar el contenido dentro de CDATA usando expresiones regulares
                        match = re.search(r'\[CDATA\[(.*?)\]\]', os_content)
                        if match:
                            os_name = match.group(1)
                        else:
                            os_name = os_content
                    else:
                        os_name = None
                    print(f"Sistema operativo encontrado: {os_name}")  # Imprimir el sistema operativo encontrado
                else:
                    print("Nodo <Os> no encontrado")

                # Agregar el host afectado único al conjunto
                unique_hosts_affected.add(start_url)

            # Crear o actualizar los objetivos para cada host afectado único
            for host in unique_hosts_affected:
                target_host, _ = Target.objects.update_or_create(
                    project=project,
                    urlAddress=host,
                    defaults={'fqdn': host, 'os': os_name}  # Guardar el sistema operativo
                )

            for scan in root.findall('.//Scan'):
                start_url = scan.find('StartURL').text if scan.find('StartURL') is not None else ''
                crawler_start_url = scan.get('StartUrl', start_url)  # Usar StartURL como fallback

                # Asignar el objetivo correspondiente a cada vulnerabilidad
                target_host = Target.objects.get(project=project, urlAddress=crawler_start_url)

                for report_item in scan.findall('.//ReportItem'):
                    name = report_item.find('Name').text
                    description = f"Description:\n{report_item.find('Description').text}\n"
                    impact = f"Impact:\n{report_item.find('Impact').text if report_item.find('Impact') is not None else ''}\n"
                    details = f"Details:\n{report_item.find('Details').text if report_item.find('Details') is not None else ''}\n"
                    recommendation = report_item.find('Recommendation').text if report_item.find('Recommendation') is not None else ''
                    severity = report_item.find('Severity').text.capitalize() if report_item.find('Severity') is not None else ''
                    technical_details = report_item.find('.//TechnicalDetails')
                    request = technical_details.find('Request').text if technical_details is not None and technical_details.find('Request') is not None else ''
                    response = ""  # Asumir que puede no haber respuesta

                    evidence = f"Request:\n{request}\nResponse:\n{response}"

                    references = ''
                    for reference in report_item.findall('.//References/Reference'):
                        database = reference.find('Database').text
                        url = reference.find('URL').text
                        references += f"{database}:\n{url}\n"

                    Vulnerability.objects.update_or_create(
                        project=project,
                        name=name,
                        defaults={
                            'description': f"{description}{impact}{details}",
                            'solution': recommendation,
                            'risk_factor': severity,
                            'evidence': evidence,
                            'see_also': references,
                            'hosts_affected': start_url,
                            'target_host': target_host  # Actualizado a target_host
                        }
                    )

            return redirect('project_detail', pk=pk)
    else:
        # Mostrar el formulario o la página correspondiente si no es un POST
        pass

    return render(request, 'admin/import_file.html', {'project': project})






def extract_links_from_references(references_element):
    if references_element is not None and references_element.text:
        # Extraer enlaces utilizando una expresión regular, por ejemplo
        links = re.findall(r'href="([^"]+)"', references_element.text)
        return "\n".join(links)
    return ""


def try_decode_base64(data):
    """
    Intenta decodificar una cadena codificada en base64 primero como utf-8.
    Si falla, devuelve una indicación de que los datos no se pudieron decodificar.
    """
    try:
        return base64.b64decode(data).decode('utf-8')
    except UnicodeDecodeError:
        return "Data not decodable"


def extract_links_from_cdata(cdata):
    soup = BeautifulSoup(cdata, "html.parser")
    links = [a['href'] for a in soup.find_all('a', href=True)]
    return "\n".join(links)


# Función auxiliar para limpiar HTML y traducir texto
def clean_and_translate_html(text, lang='es'):
    # Asumiendo que tienes una función split_and_translate(text, lang) definida en otro lugar
    cleaned_text = re.sub(r'<[^>]+>', '', text)  # Elimina etiquetas HTML
    return split_and_translate(cleaned_text, lang)


#Parser Burpsuite XML file
def import_burp_xml(request, pk):
    project = get_object_or_404(Project, pk=pk)
    if request.method == 'POST':
        form = BurpUploadForm(request.POST, request.FILES)
        if form.is_valid():
            burp_file = request.FILES['burp_file']
            tree = ET.parse(burp_file)
            root = tree.getroot()

            # Diccionario para almacenar los hosts únicos por dirección IP
            unique_hosts_by_ip = defaultdict(set)

            for item in root.findall('.//issue'):
                host_tag = item.find('host')
                ip_address = host_tag.get('ip') if host_tag is not None else ""
                host_url = host_tag.text if host_tag is not None else ""
                
                # Agregar la URL al conjunto de hosts únicos para esta dirección IP
                unique_hosts_by_ip[ip_address].add(host_url)
                
                severity = item.find('severity').text.capitalize() if item.find('severity') is not None else ""
                name = item.find('name').text if item.find('name') is not None else ""
                
                solution = clean_and_translate_html(item.find('remediationBackground').text if item.find('remediationBackground') is not None else "", 'es')
                description = clean_and_translate_html(item.find('issueBackground').text if item.find('issueBackground') is not None else "", 'es')
                
                references_element = item.find('references')
                references = extract_links_from_references(references_element)

                # Comprobando si los elementos request y response están presentes antes de intentar acceder a sus atributos text
                request_element = item.find('.//request')
                request_encoded = request_element.text if request_element is not None else ""
                response_element = item.find('.//response')
                response_encoded = response_element.text if response_element is not None else ""
                
                request_decoded = try_decode_base64(request_encoded)
                response_decoded = try_decode_base64(response_encoded)

                evidence = f"Request:\n{request_decoded}\nResponse:\n{response_decoded}"

                # Crear o actualizar los objetivos para cada dirección IP y URL única
                for ip_address, hosts in unique_hosts_by_ip.items():
                    for host_url in hosts:
                        target, _ = Target.objects.get_or_create(
                            project=project,
                            ip_address=ip_address,
                            urlAddress=host_url,
                            defaults={'urlAddress': host_url}
                        )

                # Aquí se maneja la actualización de Vulnerability para añadir hosts afectados y evidencia adicional
                vulnerability, created = Vulnerability.objects.get_or_create(
                    project=project,
                    name=name,
                    defaults={
                        'description': description,
                        'solution': solution,
                        'risk_factor': severity,
                        'evidence': evidence,
                        'see_also': references,
                        'hosts_affected': host_url
                    }
                )
                
                if not created:
                    # Añadir host afectado y evidencia adicional si la vulnerabilidad ya existía
                    if host_url not in vulnerability.hosts_affected.split('\n'):
                        vulnerability.hosts_affected += f"\n{host_url}"
                    if evidence not in vulnerability.evidence:
                        vulnerability.evidence += f"\n\n{evidence}"
                    vulnerability.save()

            return redirect('project_detail', pk=pk)
    else:
        form = BurpUploadForm()

    return render(request, 'admin/import_file.html', {'form': form, 'project': project})




def graph_view(request, pk):
    project = get_object_or_404(Project, pk=pk)
    nodes = []
    links = []
    
    # Obtener los equipos comprometidos (Owned) y las conexiones (Jumped from)
    targets = Target.objects.filter(project=project, owned=True)
    for target in targets:
        nodes.append({"id": target.ip_address, "label": target.ip_address})
        if target.jumped_from:
            links.append({
                "source": target.jumped_from.ip_address, 
                "target": target.ip_address
            })

    # Asegúrate de usar json.dumps() para enviar los datos correctamente como JSON
    context = {
        'project': project,
        'nodes': json.dumps(nodes),  # Convertir nodos en JSON
        'links': json.dumps(links),  # Convertir enlaces en JSON
    }

    print("Nodes:", nodes)
    print("Links:", links)


    return render(request, 'projectmanager/graph_map.html', context)





